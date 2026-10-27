package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

var (
	_ resource.Resource                   = (*endpointOIDCProviderResource)(nil)
	_ resource.ResourceWithConfigure      = (*endpointOIDCProviderResource)(nil)
	_ resource.ResourceWithImportState    = (*endpointOIDCProviderResource)(nil)
	_ resource.ResourceWithValidateConfig = (*endpointOIDCProviderResource)(nil)
)

func newEndpointOIDCProviderResource() resource.Resource { return &endpointOIDCProviderResource{} }

type endpointOIDCProviderResource struct {
	client *client.Client
}

type endpointOIDCProviderModel struct {
	ID                    types.String `tfsdk:"id"`
	Name                  types.String `tfsdk:"name"`
	ClientID              types.String `tfsdk:"client_id"`
	ClientSecret          types.String `tfsdk:"client_secret"`
	ClientSecretWO        types.String `tfsdk:"client_secret_wo"`
	ClientSecretWOVersion types.Int64  `tfsdk:"client_secret_wo_version"`
	IssuerURL             types.String `tfsdk:"issuer_url"`
	Enabled               types.Bool   `tfsdk:"enabled"`
	NetworkID             types.String `tfsdk:"network_id"`
	RoleID                types.String `tfsdk:"role_id"`
	AuthValidityHours     types.Int64  `tfsdk:"auth_validity_hours"`
	DomainID              types.String `tfsdk:"domain_id"`
	AutoAssignCIDRs       types.Set    `tfsdk:"auto_assign_cidrs"`
}

func (r *endpointOIDCProviderResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_endpoint_oidc_provider"
}

func (r *endpointOIDCProviderResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an endpoint OIDC provider: the identity provider hosts on a network sign in with " +
			"(endpoint SSO). An enabled provider needs a verified domain; reference `domain_id` from a " +
			"`definednet_domain_verification` so the provider is created after verification.\n\n" +
			"The client secret is supplied either as `client_secret`, which is stored in state, or as `client_secret_wo` " +
			"with `client_secret_wo_version`, which is never stored (Terraform 1.11 / OpenTofu 1.11 or newer). The API " +
			"never returns the secret, so Terraform cannot detect a secret changed outside Terraform; every update " +
			"re-sends the configured one.\n\n" +
			"The API runs OIDC discovery against `issuer_url` on every create and update, so any update, including a " +
			"secret rotation, fails while the identity provider's discovery endpoint is unreachable.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Provider ID, e.g. `endpointoidc-X47KHSCOSQJP5IOKNNKRRGHVAI`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Provider name, 1-50 characters, unique within the organization.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.UTF8LengthBetween(1, 50)},
			},
			"client_id": schema.StringAttribute{
				MarkdownDescription: "OAuth client ID issued by the identity provider, 1-255 characters.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthBetween(1, 255)},
			},
			"client_secret": schema.StringAttribute{
				MarkdownDescription: "OAuth client secret, stored in state. Exactly one of `client_secret` and `client_secret_wo` must be set.",
				Optional:            true,
				Sensitive:           true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 255),
					stringvalidator.ExactlyOneOf(path.MatchRoot("client_secret_wo")),
				},
			},
			"client_secret_wo": schema.StringAttribute{
				MarkdownDescription: "OAuth client secret as a write-only argument: sent to the API but never stored in plan or state. " +
					"Requires `client_secret_wo_version`; change the version to re-send a rotated secret.",
				Optional:  true,
				WriteOnly: true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 255),
					stringvalidator.AlsoRequires(path.MatchRoot("client_secret_wo_version")),
				},
			},
			"client_secret_wo_version": schema.Int64Attribute{
				MarkdownDescription: "Version counter for `client_secret_wo`. Terraform cannot see the write-only value, so increment this to trigger an update that re-sends it.",
				Optional:            true,
				Validators:          []validator.Int64{int64validator.AlsoRequires(path.MatchRoot("client_secret_wo"))},
			},
			"issuer_url": schema.StringAttribute{
				MarkdownDescription: "OIDC issuer URL, e.g. `https://accounts.google.com`. Must be https.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 255),
					stringvalidator.RegexMatches(regexp.MustCompile(`^https://`), "must be an https URL"),
				},
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether hosts may sign in through this provider. Requires `domain_id`, and the domain must be verified. Defaults to `false`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"network_id": schema.StringAttribute{
				MarkdownDescription: "Network that hosts enrolling through this provider join.",
				Required:            true,
			},
			"role_id": schema.StringAttribute{
				MarkdownDescription: "Role assigned to hosts enrolling through this provider.",
				Optional:            true,
			},
			"auth_validity_hours": schema.Int64Attribute{
				MarkdownDescription: "How long a sign-in stays valid, 1 to 43800 hours. Omit for the API default.",
				Optional:            true,
				Validators:          []validator.Int64{int64validator.Between(1, 43800)},
			},
			"domain_id": schema.StringAttribute{
				MarkdownDescription: "Verified domain users must belong to. Required when `enabled` is true; only one enabled provider may hold a domain.",
				Optional:            true,
			},
			"auto_assign_cidrs": schema.SetAttribute{
				MarkdownDescription: "IPv4 prefix hosts enrolling through this provider draw addresses from: either empty or the network's own " +
					"`ipv4_cidr`, which the API rejects any other prefix for. IPv6 is always assigned and is not listed here; the full stored " +
					"list is the network's `cidrs`. Omit to accept the server's value (and the new network's default when `network_id` changes), " +
					"set `[]` to assign IPv6 only. On a certificate version 1 network the API always assigns IPv4, so `[]` there shows a diff on every plan.",
				Optional:      true,
				Computed:      true,
				ElementType:   types.StringType,
				PlanModifiers: []planmodifier.Set{keepAutoAssignForSameNetwork{}},
				Validators:    []validator.Set{setvalidator.ValueStringsAre(ipv4PrefixValidator{})},
			},
		},
	}
}

// keepAutoAssignForSameNetwork is UseStateForUnknown restricted to plans that
// keep network_id. The stored value is the old network's own IPv4 CIDR, which
// the API rejects for any other network, so a network change leaves the value
// unknown and the request sends no list, letting the API apply the new
// network's default.
type keepAutoAssignForSameNetwork struct{}

func (keepAutoAssignForSameNetwork) Description(_ context.Context) string {
	return "keeps the prior value when unset, unless network_id changes"
}

func (m keepAutoAssignForSameNetwork) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (keepAutoAssignForSameNetwork) PlanModifySet(ctx context.Context, req planmodifier.SetRequest, resp *planmodifier.SetResponse) {
	if req.State.Raw.IsNull() || !req.PlanValue.IsUnknown() || req.StateValue.IsUnknown() {
		return
	}
	var planNet, stateNet types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("network_id"), &planNet)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("network_id"), &stateNet)...)
	if resp.Diagnostics.HasError() || !planNet.Equal(stateNet) {
		return
	}
	resp.PlanValue = req.StateValue
}

// ValidateConfig mirrors the API's Bind rule so a missing domain fails at plan time.
func (r *endpointOIDCProviderResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg endpointOIDCProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if cfg.Enabled.ValueBool() && cfg.DomainID.IsNull() {
		resp.Diagnostics.AddAttributeError(path.Root("domain_id"), "Missing domain_id",
			"domain_id must be set when enabled is true. Reference definednet_domain_verification.<name>.domain_id so the domain is verified first.")
	}
}

func (r *endpointOIDCProviderResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *endpointOIDCProviderResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan endpointOIDCProviderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body, diags := r.expand(ctx, plan, req.Config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	p, err := r.client.CreateEndpointOIDCProvider(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create endpoint OIDC provider", fmt.Sprintf("provider %q: %s", plan.Name.ValueString(), describeError(err)))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, p, plan, &resp.State)...)
}

func (r *endpointOIDCProviderResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state endpointOIDCProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	p, err := r.client.GetEndpointOIDCProvider(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read endpoint OIDC provider", fmt.Sprintf("provider %q: %s", state.ID.ValueString(), err))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, p, state, &resp.State)...)
}

func (r *endpointOIDCProviderResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan endpointOIDCProviderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body, diags := r.expand(ctx, plan, req.Config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	p, err := r.client.UpdateEndpointOIDCProvider(ctx, plan.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("Unable to update endpoint OIDC provider", fmt.Sprintf("provider %q: %s", plan.ID.ValueString(), describeError(err)))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, p, plan, &resp.State)...)
}

func (r *endpointOIDCProviderResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state endpointOIDCProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteEndpointOIDCProvider(ctx, state.ID.ValueString())
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete endpoint OIDC provider", fmt.Sprintf("provider %q: %s", state.ID.ValueString(), describeError(err)))
	}
}

func (r *endpointOIDCProviderResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// configGetter is satisfied by tfsdk.Config; the write-only secret exists only there.
type configGetter interface {
	GetAttribute(ctx context.Context, p path.Path, target any) diag.Diagnostics
}

// expand builds the request. The secret always comes from configuration: the
// stored variant through the plan, the write-only variant straight from config
// since plan and state hold null for it. ExactlyOneOf guarantees one of them
// once values are known, but it skips unknowns, so a value that resolves to
// null at apply is caught here rather than reaching the API's "null keeps the
// old secret" path.
func (r *endpointOIDCProviderResource) expand(ctx context.Context, plan endpointOIDCProviderModel, cfg configGetter) (client.EndpointOIDCProviderRequest, diag.Diagnostics) {
	var diags diag.Diagnostics
	body := client.EndpointOIDCProviderRequest{
		Name:              plan.Name.ValueString(),
		ClientID:          plan.ClientID.ValueString(),
		ClientSecret:      optionalString(plan.ClientSecret),
		IssuerURL:         plan.IssuerURL.ValueString(),
		Enabled:           plan.Enabled.ValueBool(),
		NetworkID:         plan.NetworkID.ValueString(),
		RoleID:            optionalString(plan.RoleID),
		AuthValidityHours: plan.AuthValidityHours.ValueInt64Pointer(),
		DomainID:          optionalString(plan.DomainID),
	}
	if body.ClientSecret == nil {
		var wo types.String
		diags.Append(cfg.GetAttribute(ctx, path.Root("client_secret_wo"), &wo)...)
		body.ClientSecret = optionalString(wo)
	}
	if body.ClientSecret == nil {
		diags.AddAttributeError(path.Root("client_secret"), "Missing client secret",
			"exactly one of client_secret and client_secret_wo must resolve to a value")
	}
	if !plan.AutoAssignCIDRs.IsNull() && !plan.AutoAssignCIDRs.IsUnknown() {
		diags.Append(plan.AutoAssignCIDRs.ElementsAs(ctx, &body.AutoAssignCIDRs, false)...)
	}
	return body, diags
}

// setState writes the API object plus the values the API cannot return: the
// stored secret and the write-only version counter are carried from prior (the
// plan on writes, the state on refresh). The write-only secret itself is nulled
// by the framework. auto_assign_cidrs is the API's IPv4 entries only: IPv6 is
// forced by the API, so keeping it out of state leaves one owner for the value
// that is actually a choice, and drift and import both show the real opt-in.
func (r *endpointOIDCProviderResource) setState(ctx context.Context, p *client.EndpointOIDCProvider, prior endpointOIDCProviderModel, state stateSetter) diag.Diagnostics {
	v4 := []string{}
	for _, c := range p.AutoAssignCIDRs {
		if !strings.Contains(c, ":") {
			v4 = append(v4, c)
		}
	}
	cidrs, diags := types.SetValueFrom(ctx, types.StringType, v4)
	m := endpointOIDCProviderModel{
		ID:                    types.StringValue(p.ID),
		Name:                  types.StringValue(p.Name),
		ClientID:              types.StringValue(p.ClientID),
		ClientSecret:          prior.ClientSecret,
		ClientSecretWO:        types.StringNull(),
		ClientSecretWOVersion: prior.ClientSecretWOVersion,
		IssuerURL:             types.StringValue(p.IssuerURL),
		Enabled:               types.BoolValue(p.Enabled),
		NetworkID:             types.StringValue(p.NetworkID),
		RoleID:                types.StringPointerValue(p.RoleID),
		AuthValidityHours:     types.Int64PointerValue(p.AuthValidityHours),
		DomainID:              types.StringPointerValue(p.DomainID),
		AutoAssignCIDRs:       cidrs,
	}
	diags.Append(state.Set(ctx, &m)...)
	return diags
}
