package provider

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

var (
	_ resource.Resource                = (*joinKeyResource)(nil)
	_ resource.ResourceWithConfigure   = (*joinKeyResource)(nil)
	_ resource.ResourceWithImportState = (*joinKeyResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*joinKeyResource)(nil)
)

// joinKeyNameRegexp mirrors the API: the name becomes part of enrolled hosts'
// names, so it must be a DNS label.
var joinKeyNameRegexp = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

func newJoinKeyResource() resource.Resource { return &joinKeyResource{} }

type joinKeyResource struct {
	client *client.Client
}

type joinKeyModel struct {
	ID              types.String `tfsdk:"id"`
	Name            types.String `tfsdk:"name"`
	NetworkID       types.String `tfsdk:"network_id"`
	RoleID          types.String `tfsdk:"role_id"`
	Tags            types.Set    `tfsdk:"tags"`
	AutoAssignCIDRs types.Set    `tfsdk:"auto_assign_cidrs"`
	ExpiresAt       types.String `tfsdk:"expires_at"`
	Token           types.String `tfsdk:"token"`
}

func (r *joinKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_join_key"
}

func (r *joinKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a join key: a reusable secret that enrolls any number of hosts into one network with the key's " +
			"role, tags, and address prefixes. Each enrollment creates a new host named after the enrolling machine's hostname, or after the key when that is unusable; those hosts are not " +
			"managed by Terraform. Use `definednet_host` instead for " +
			"hosts whose identity must exist before they boot, such as lighthouses and relays.\n\n" +
			"The API key needs the `join-keys:create`, `join-keys:read`, `join-keys:update`, and `join-keys:delete` scopes, " +
			"and the organization needs join keys enabled.\n\n" +
			"Only `name` and `expires_at` can change in place; any other change replaces the key, which issues a new `token` " +
			"and leaves the old one unusable. Deleting a key does not remove the hosts that enrolled with it. " +
			"A replacement deletes the old key before creating the new one; to rotate a key with no gap, set " +
			"`lifecycle { create_before_destroy = true }` and change `name` in the same apply, because names are unique.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Join key ID, e.g. `dnjoin-PH7SNGBJJ5MLLXOWQ7HGMRAPOQ`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Key name, unique within the organization: 1-54 lowercase letters, digits, and hyphens, " +
					"not starting or ending with a hyphen. Hosts enrolled with the key are named after it.",
				Required: true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 54),
					stringvalidator.RegexMatches(joinKeyNameRegexp, "must contain only lowercase letters, digits, and hyphens, and must not start or end with a hyphen"),
				},
			},
			"network_id": schema.StringAttribute{
				MarkdownDescription: "Network that enrolled hosts join. Changing it replaces the key.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"role_id": schema.StringAttribute{
				MarkdownDescription: "Role given to enrolled hosts. Changing it replaces the key.",
				Optional:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"tags": schema.SetAttribute{
				MarkdownDescription: "Tags given to enrolled hosts, in `key:value` form. Changing them replaces the key.",
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				Default:             setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
				PlanModifiers:       []planmodifier.Set{setplanmodifier.RequiresReplace()},
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(stringvalidator.RegexMatches(tagNameRegexp, "must be a key:value tag with no surrounding whitespace")),
				},
			},
			"auto_assign_cidrs": schema.SetAttribute{
				MarkdownDescription: "IPv4 prefix enrolled hosts draw addresses from: either empty or the network's own `ipv4_cidr`, " +
					"which the API rejects any other prefix for. IPv6 is always assigned and is not listed here. Omit to accept " +
					"the server's value, which on a dual-stack network is IPv6 only; set `[]` to assign IPv6 only explicitly. Changing it replaces the key. On a certificate version 1 " +
					"network always assigns IPv4, so the API rejects `[]` there and the provider rejects it at plan time; setting `[]` needs the `networks:read` scope, because the " +
					"provider reads the network to check its certificate version. When `network_id` is unknown at plan time, the check runs only during " +
					"apply, after a replacement may already have deleted the old key.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				PlanModifiers: []planmodifier.Set{
					keepAutoAssignForSameNetwork{},
					setplanmodifier.RequiresReplace(),
				},
				Validators: []validator.Set{setvalidator.ValueStringsAre(ipv4PrefixValidator{})},
			},
			"expires_at": schema.StringAttribute{
				MarkdownDescription: "When the key stops working, as an RFC 3339 timestamp in UTC with whole seconds, e.g. `2027-01-01T00:00:00Z`. " +
					"Must be in the future when set or changed. Omit for a key that never expires.",
				Optional:   true,
				Validators: []validator.String{utcTimestampValidator{}},
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "The secret hosts enroll with, `dnjoin-...`. The API returns it only when the key is created, " +
					"so it is null after `terraform import`.",
				Computed:      true,
				Sensitive:     true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *joinKeyResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *joinKeyResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	rejectEmptyAutoAssignOnCertV1(ctx, r.client, req, resp)
}

func (r *joinKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan joinKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := client.JoinKeyCreateRequest{
		Name:      plan.Name.ValueString(),
		NetworkID: plan.NetworkID.ValueString(),
		RoleID:    optionalString(plan.RoleID),
		ExpiresAt: parseTimestamp(plan.ExpiresAt),
	}
	var diags diag.Diagnostics
	body.Tags, diags = expandStringSet(ctx, plan.Tags)
	resp.Diagnostics.Append(diags...)
	if !plan.AutoAssignCIDRs.IsNull() && !plan.AutoAssignCIDRs.IsUnknown() {
		resp.Diagnostics.Append(plan.AutoAssignCIDRs.ElementsAs(ctx, &body.AutoAssignCIDRs, false)...)
	}
	if resp.Diagnostics.HasError() {
		return
	}

	k, err := r.client.CreateJoinKey(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create join key", fmt.Sprintf("join key %q: %s", plan.Name.ValueString(), describeError(err)))
		return
	}

	plan.Token = types.StringValue(k.Token)
	resp.Diagnostics.Append(r.setState(ctx, &k.JoinKey, plan, &resp.State)...)
}

func (r *joinKeyResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state joinKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	k, err := r.client.GetJoinKey(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read join key", fmt.Sprintf("join key %q: %s", state.ID.ValueString(), err))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, k, state, &resp.State)...)
}

// Update sends only the fields that changed. Re-sending an unchanged expiry
// would fail once that time has passed, since the API rejects past expiries.
func (r *joinKeyResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state joinKeyModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var body client.JoinKeyPatchRequest
	if !plan.Name.Equal(state.Name) {
		body.Name = plan.Name.ValueStringPointer()
	}
	if !plan.ExpiresAt.Equal(state.ExpiresAt) {
		t := parseTimestamp(plan.ExpiresAt)
		body.ExpiresAt = &t
	}

	k, err := r.client.UpdateJoinKey(ctx, plan.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("Unable to update join key", fmt.Sprintf("join key %q: %s", plan.ID.ValueString(), describeError(err)))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, k, plan, &resp.State)...)
}

func (r *joinKeyResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state joinKeyModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteJoinKey(ctx, state.ID.ValueString())
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete join key", fmt.Sprintf("join key %q: %s", state.ID.ValueString(), describeError(err)))
	}
}

func (r *joinKeyResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// setState writes the API key plus the token, which only the create response
// carries and so is always taken from prior. auto_assign_cidrs keeps only the
// IPv4 entries, as on endpoint OIDC providers.
func (r *joinKeyResource) setState(ctx context.Context, k *client.JoinKey, prior joinKeyModel, state stateSetter) diag.Diagnostics {
	var diags diag.Diagnostics
	tags, d := types.SetValueFrom(ctx, types.StringType, nonNilStrings(k.Tags))
	diags.Append(d...)
	cidrs, d := types.SetValueFrom(ctx, types.StringType, ipv4Only(k.AutoAssignCIDRs))
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}

	m := joinKeyModel{
		ID:              types.StringValue(k.ID),
		Name:            types.StringValue(k.Name),
		NetworkID:       types.StringValue(k.NetworkID),
		RoleID:          types.StringPointerValue(k.RoleID),
		Tags:            tags,
		AutoAssignCIDRs: cidrs,
		Token:           prior.Token,
	}
	if k.ExpiresAt != nil {
		m.ExpiresAt = types.StringValue(k.ExpiresAt.UTC().Format(time.RFC3339))
	}
	diags.Append(state.Set(ctx, &m)...)
	return diags
}

// parseTimestamp converts a validated RFC 3339 attribute to a time, nil when null.
func parseTimestamp(s types.String) *time.Time {
	if s.IsNull() || s.IsUnknown() {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s.ValueString())
	if err != nil {
		return nil
	}
	return &t
}
