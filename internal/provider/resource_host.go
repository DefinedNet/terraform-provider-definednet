package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

var (
	_ resource.Resource                   = (*hostResource)(nil)
	_ resource.ResourceWithConfigure      = (*hostResource)(nil)
	_ resource.ResourceWithImportState    = (*hostResource)(nil)
	_ resource.ResourceWithValidateConfig = (*hostResource)(nil)
)

func newHostResource() resource.Resource { return &hostResource{} }

type hostResource struct {
	client *client.Client
}

type hostModel struct {
	ID              types.String `tfsdk:"id"`
	NetworkID       types.String `tfsdk:"network_id"`
	Name            types.String `tfsdk:"name"`
	RoleID          types.String `tfsdk:"role_id"`
	IsLighthouse    types.Bool   `tfsdk:"is_lighthouse"`
	IsRelay         types.Bool   `tfsdk:"is_relay"`
	StaticAddresses types.Set    `tfsdk:"static_addresses"`
	ListenPort      types.Int64  `tfsdk:"listen_port"`
	Tags            types.Set    `tfsdk:"tags"`
	ConfigOverrides types.Set    `tfsdk:"config_overrides"`
	IPv4Address     types.String `tfsdk:"ipv4_address"`
	IPAddresses     types.List   `tfsdk:"ip_addresses"`
	IsBlocked       types.Bool   `tfsdk:"is_blocked"`

	EnrollmentCode                types.String `tfsdk:"enrollment_code"`
	EnrollmentCodeTriggers        types.Map    `tfsdk:"enrollment_code_triggers"`
	EnrollmentCodeLifetimeSeconds types.Int64  `tfsdk:"enrollment_code_lifetime_seconds"`
}

func (r *hostResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_host"
}

func (r *hostResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a host record: the identity, addresses, role, and tags a machine gets when it enrolls. " +
			"Use it for lighthouses, relays, and other hosts whose identity must exist before they boot; enroll fleets " +
			"with a `definednet_join_key` instead, whose hosts stay outside Terraform.\n\n" +
			"Creating the host mints a single-use `enrollment_code`; pass it to the machine, for example through " +
			"cloud-init user data, and dnclient redeems it to enroll as this host. Terraform does not track enrollment. " +
			"The code dies at first use, so a rebuilt machine needs a new one: put whatever replaces the machine, such " +
			"as its AMI ID, in `enrollment_code_triggers`, and the new code flows into the user data in the same apply " +
			"(with `aws_instance`, set `user_data_replace_on_change = true`). A machine replaced for any other reason, " +
			"such as `-replace`, a taint, a failed provision retried later, or a termination outside Terraform, reuses " +
			"the stored code, which may be consumed or expired; change a trigger value in the same apply. Terraform " +
			"destroys the old instance before " +
			"it re-mints the code, so unblock a blocked host first. Re-enrolling keeps the record and its addresses but " +
			"does not revoke the previous machine's certificate; run one machine per host. To give a rebuilt machine a " +
			"new record instead, replace the host with `lifecycle { replace_triggered_by }` pointing at a resource " +
			"upstream of the machine, such as a `terraform_data` holding the AMI ID; pointing at the machine itself " +
			"is a cycle once it uses the code.\n\n" +
			"The API key needs the `hosts:create`, `hosts:read`, `hosts:update`, `hosts:delete`, and `hosts:enroll` " +
			"scopes, plus `networks:read` when `ipv4_address` is omitted.\n\n" +
			"A replacement deletes the old host before creating the new one; with `lifecycle { create_before_destroy = true }` " +
			"the new host also needs a different `name`, and a different `ipv4_address` if one is set, because both are unique within the network.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Host ID, e.g. `host-24NVITAMHMJ6WU2OXDL63L4JCI`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"network_id": schema.StringAttribute{
				MarkdownDescription: "Network the host belongs to. Changing it replaces the host.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Host name, 1-255 characters, unique within the network. `any` is reserved.",
				Required:            true,
				Validators: []validator.String{
					stringvalidator.UTF8LengthBetween(1, 255),
					stringvalidator.NoneOfCaseInsensitive("any"),
				},
			},
			"role_id": schema.StringAttribute{
				MarkdownDescription: "Role whose firewall rules apply to the host.",
				Optional:            true,
			},
			"is_lighthouse": schema.BoolAttribute{
				MarkdownDescription: "Whether the host is a lighthouse. A lighthouse needs `static_addresses` and a non-zero " +
					"`listen_port`, and cannot also be a relay. Changing it replaces the host. Defaults to `false`.",
				Optional:      true,
				Computed:      true,
				Default:       booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()},
			},
			"is_relay": schema.BoolAttribute{
				MarkdownDescription: "Whether the host is a relay. A relay needs a non-zero `listen_port`. Changing it replaces " +
					"the host. Defaults to `false`.",
				Optional:      true,
				Computed:      true,
				Default:       booldefault.StaticBool(false),
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()},
			},
			"static_addresses": schema.SetAttribute{
				MarkdownDescription: "Public `ip:port` or `hostname:port` addresses other hosts reach this one at, at most 100. " +
					"Nebula tries every address, so order carries no meaning and the API drops duplicates.",
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Default:     setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
				Validators:  []validator.Set{setvalidator.SizeAtMost(100)},
			},
			"listen_port": schema.Int64Attribute{
				MarkdownDescription: "UDP port Nebula listens on, 0-65535. `0` picks a random port, which lighthouses and relays " +
					"cannot use. Defaults to `0`.",
				Optional:   true,
				Computed:   true,
				Default:    int64default.StaticInt64(0),
				Validators: []validator.Int64{int64validator.Between(0, 65535)},
			},
			"tags": schema.SetAttribute{
				MarkdownDescription: "Tags in `key:value` form. Tags that do not exist yet are created by the API.",
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				Default:             setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
				Validators: []validator.Set{
					setvalidator.ValueStringsAre(stringvalidator.RegexMatches(tagNameRegexp, "must be a key:value tag with no surrounding whitespace")),
				},
			},
			"config_overrides": configOverridesSchema("Nebula config overrides for this host, which win over its tags' and network's. " +
				"`value` is JSON, so use `jsonencode()`."),
			"ipv4_address": schema.StringAttribute{
				MarkdownDescription: "Overlay IPv4 address, inside the network's `ipv4_cidr`. Omit to have the API assign the next " +
					"free address at creation, or none on a network without IPv4. A host without one, such as a host created " +
					"before its network gained an `ipv4_cidr`, gets the configured address in place; changing an existing " +
					"address replaces the host.",
				Optional:   true,
				Computed:   true,
				Validators: []validator.String{ipv4AddressValidator{}},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplaceIf(ipv4AddressRequiresReplace,
						"Changing an existing IPv4 address requires a new host.",
						"Changing an existing IPv4 address requires a new host."),
				},
			},
			"ip_addresses": schema.ListAttribute{
				MarkdownDescription: "Every overlay address the host has, IPv4 first. Hosts on a network with an IPv6 prefix always get an IPv6 address.",
				Computed:            true,
				ElementType:         types.StringType,
				PlanModifiers:       []planmodifier.List{ipAddressesUseStateUnlessIPv4Added{}},
			},
			"is_blocked": schema.BoolAttribute{
				MarkdownDescription: "Whether the host is blocked from the network. Blocking is managed outside Terraform; a " +
					"blocked host cannot enroll or connect.",
				Computed:      true,
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"enrollment_code": schema.StringAttribute{
				MarkdownDescription: "Single-use code dnclient redeems to enroll a machine as this host, minted at creation " +
					"and again whenever `enrollment_code_triggers` changes. The API never returns it afterwards, so it " +
					"is null after import until the triggers change.",
				Computed:      true,
				Sensitive:     true,
				PlanModifiers: []planmodifier.String{enrollmentCodeUseStateUnlessReminted{}},
			},
			"enrollment_code_triggers": schema.MapAttribute{
				MarkdownDescription: "Arbitrary values whose change, including removing the map, mints a new " +
					"`enrollment_code`, such as the machine's AMI ID. The host record itself is unchanged. On an existing " +
					"host the values must be known at plan time, so the plan can say whether a code will be minted.",
				Optional:    true,
				ElementType: types.StringType,
			},
			"enrollment_code_lifetime_seconds": schema.Int64Attribute{
				MarkdownDescription: "How long the next minted code stays redeemable, 60-604800 seconds. Omit for the " +
					"API default of 86400 (one day). Changing it alone does not mint a new code.",
				Optional:   true,
				Validators: []validator.Int64{int64validator.Between(60, 604800)},
			},
		},
	}
}

// ValidateConfig mirrors the API's lighthouse and relay rules so they fail at plan time.
func (r *hostResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg hostModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	lighthouse, relay := cfg.IsLighthouse.ValueBool(), cfg.IsRelay.ValueBool()
	if lighthouse && relay {
		resp.Diagnostics.AddAttributeError(path.Root("is_relay"), "Invalid host role",
			"A lighthouse cannot also be a relay.")
	}
	if (lighthouse || relay) && !cfg.ListenPort.IsUnknown() && cfg.ListenPort.ValueInt64() == 0 {
		resp.Diagnostics.AddAttributeError(path.Root("listen_port"), "Missing listen_port",
			"Lighthouses and relays need a non-zero listen_port.")
	}
	if lighthouse && !cfg.StaticAddresses.IsUnknown() && len(cfg.StaticAddresses.Elements()) == 0 {
		resp.Diagnostics.AddAttributeError(path.Root("static_addresses"), "Missing static_addresses",
			"Lighthouses need at least one static address.")
	}
}

func (r *hostResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *hostResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan hostModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := client.HostAndEnrollmentCodeCreateRequest{
		HostCreateRequest: client.HostCreateRequest{
			NetworkID:    plan.NetworkID.ValueString(),
			RoleID:       optionalString(plan.RoleID),
			Name:         plan.Name.ValueString(),
			ListenPort:   plan.ListenPort.ValueInt64(),
			IsLighthouse: plan.IsLighthouse.ValueBool(),
			IsRelay:      plan.IsRelay.ValueBool(),
			IPAddresses:  []string{},
		},
		CodeLifetimeSeconds: optionalInt64(plan.EnrollmentCodeLifetimeSeconds),
	}
	var diags diag.Diagnostics
	body.StaticAddresses, diags = expandStringSet(ctx, plan.StaticAddresses)
	resp.Diagnostics.Append(diags...)
	body.Tags, diags = expandStringSet(ctx, plan.Tags)
	resp.Diagnostics.Append(diags...)
	body.ConfigOverrides, diags = expandConfigOverrides(ctx, plan.ConfigOverrides)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if a := optionalString(plan.IPv4Address); a != nil {
		body.IPAddresses = []string{*a}
	} else {
		// The API assigns IPv4 on a dual-stack network only when asked with the
		// network's prefix, so look it up to match the admin panel's default.
		n, err := r.client.GetNetwork(ctx, body.NetworkID)
		if err != nil {
			resp.Diagnostics.AddError("Unable to create host",
				fmt.Sprintf("host %q: reading network %q to assign an IPv4 address: %s", body.Name, body.NetworkID, err))
			return
		}
		body.IPAddresses = ipv4Only(n.CIDRs)
	}

	hc, err := r.client.CreateHostAndEnrollmentCode(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create host", fmt.Sprintf("host %q: %s", body.Name, describeError(err)))
		return
	}

	plan.EnrollmentCode = types.StringValue(hc.EnrollmentCode.Code)
	resp.Diagnostics.Append(r.setState(ctx, &hc.Host, plan, &resp.State)...)
}

func (r *hostResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state hostModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	h, err := r.client.GetHost(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read host", fmt.Sprintf("host %q: %s", state.ID.ValueString(), err))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, h, state, &resp.State)...)
}

func (r *hostResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state hostModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body, diags := hostUpdateBody(ctx, plan)
	resp.Diagnostics.Append(diags...)
	prior, diags := hostUpdateBody(ctx, state)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Every state written before the mint succeeds keeps the previous code and
	// triggers, so a failed mint leaves the trigger change pending for the next
	// apply instead of recording a code that was never minted.
	committed := plan
	committed.EnrollmentCode, committed.EnrollmentCodeTriggers = state.EnrollmentCode, state.EnrollmentCodeTriggers

	// The host as last returned by the API; nil when no request has run, in
	// which case the plan already holds every value.
	var h *client.Host
	save := func(m hostModel) {
		if h != nil {
			resp.Diagnostics.Append(r.setState(ctx, h, m, &resp.State)...)
		} else {
			resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
		}
	}

	// The PUT cannot set addresses; the add-IP route only fills a missing IPv4.
	// It goes first so a rejected address leaves the host untouched, and its
	// result is saved before the PUT so a failing PUT does not drop the address
	// from state, where a retry without refresh would add it again and fail.
	if state.IPv4Address.IsNull() && !plan.IPv4Address.IsNull() {
		var err error
		h, err = r.client.AddHostIPAddress(ctx, plan.ID.ValueString(), plan.IPv4Address.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Unable to update host",
				fmt.Sprintf("host %q: adding IPv4 address %q: %s", plan.ID.ValueString(), plan.IPv4Address.ValueString(), describeError(err)))
			return
		}
		save(committed)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	// The PUT is a full replacement that writes an audit entry even when nothing
	// changes, so an address- or code-only apply leaves it out.
	if !samePUTFields(body, prior) {
		var err error
		h, err = r.client.UpdateHost(ctx, plan.ID.ValueString(), body)
		if err != nil {
			resp.Diagnostics.AddError("Unable to update host", fmt.Sprintf("host %q: %s", plan.ID.ValueString(), describeError(err)))
			return
		}
	}
	save(committed)
	// The plan modifier owns the mint decision: an unknown planned code is the
	// promise of a new one, and the plan modifier made it from known triggers,
	// so the apply-time replan reaches the same answer.
	if resp.Diagnostics.HasError() || !plan.EnrollmentCode.IsUnknown() {
		return
	}

	code, err := r.client.CreateEnrollmentCode(ctx, plan.ID.ValueString(), optionalInt64(plan.EnrollmentCodeLifetimeSeconds))
	if err != nil {
		resp.Diagnostics.AddError("Unable to update host",
			fmt.Sprintf("host %q: minting an enrollment code: %s", plan.ID.ValueString(), describeError(err)))
		return
	}
	plan.EnrollmentCode = types.StringValue(code.Code)
	save(plan)
}

// hostUpdateBody projects the fields PUT /v3/hosts/{id} owns.
func hostUpdateBody(ctx context.Context, m hostModel) (client.HostUpdateRequest, diag.Diagnostics) {
	body := client.HostUpdateRequest{
		Name:       m.Name.ValueString(),
		RoleID:     optionalString(m.RoleID),
		ListenPort: m.ListenPort.ValueInt64(),
	}
	var diags, d diag.Diagnostics
	body.StaticAddresses, d = expandStringSet(ctx, m.StaticAddresses)
	diags.Append(d...)
	body.Tags, d = expandStringSet(ctx, m.Tags)
	diags.Append(d...)
	body.ConfigOverrides, d = expandConfigOverrides(ctx, m.ConfigOverrides)
	diags.Append(d...)
	return body, diags
}

// samePUTFields reports whether two PUT bodies describe the same host. Sets
// carry no order, and override values are JSON whose spelling may differ.
func samePUTFields(a, b client.HostUpdateRequest) bool {
	sorted := func(s []string) []string { s = slices.Clone(s); slices.Sort(s); return s }
	overrideKey := func(o client.ConfigOverride) string { return o.Key + "=" + canonicalJSON(o.Value) }
	return a.Name == b.Name && a.ListenPort == b.ListenPort &&
		optionalStringEqual(a.RoleID, b.RoleID) &&
		slices.Equal(sorted(a.StaticAddresses), sorted(b.StaticAddresses)) &&
		slices.Equal(sorted(a.Tags), sorted(b.Tags)) &&
		slices.Equal(sorted(mapSlice(a.ConfigOverrides, overrideKey)), sorted(mapSlice(b.ConfigOverrides, overrideKey)))
}

func optionalStringEqual(a, b *string) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func mapSlice[T, U any](in []T, f func(T) U) []U {
	out := make([]U, len(in))
	for i, v := range in {
		out[i] = f(v)
	}
	return out
}

func (r *hostResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state hostModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteHost(ctx, state.ID.ValueString())
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete host", fmt.Sprintf("host %q: %s", state.ID.ValueString(), describeError(err)))
	}
}

func (r *hostResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *hostResource) setState(ctx context.Context, h *client.Host, ref hostModel, state stateSetter) diag.Diagnostics {
	var diags diag.Diagnostics
	static, d := types.SetValueFrom(ctx, types.StringType, nonNilStrings(h.StaticAddresses))
	diags.Append(d...)
	tags, d := types.SetValueFrom(ctx, types.StringType, nonNilStrings(h.Tags))
	diags.Append(d...)
	overrides, d := flattenConfigOverrides(ctx, h.ConfigOverrides, ref.ConfigOverrides)
	diags.Append(d...)
	ips, d := types.ListValueFrom(ctx, types.StringType, nonNilStrings(h.IPAddresses))
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}

	ipv4 := types.StringNull()
	for _, a := range h.IPAddresses {
		if !strings.Contains(a, ":") {
			ipv4 = types.StringValue(a)
		}
	}

	m := hostModel{
		ID:              types.StringValue(h.ID),
		NetworkID:       types.StringValue(h.NetworkID),
		Name:            types.StringValue(h.Name),
		RoleID:          types.StringPointerValue(h.RoleID),
		IsLighthouse:    types.BoolValue(h.IsLighthouse),
		IsRelay:         types.BoolValue(h.IsRelay),
		StaticAddresses: static,
		ListenPort:      types.Int64Value(h.ListenPort),
		Tags:            tags,
		ConfigOverrides: overrides,
		IPv4Address:     ipv4,
		IPAddresses:     ips,
		IsBlocked:       types.BoolValue(h.IsBlocked),

		// GET never returns these; the last mint, or the caller, is the source.
		EnrollmentCode:                ref.EnrollmentCode,
		EnrollmentCodeTriggers:        ref.EnrollmentCodeTriggers,
		EnrollmentCodeLifetimeSeconds: ref.EnrollmentCodeLifetimeSeconds,
	}
	diags.Append(state.Set(ctx, &m)...)
	return diags
}

// ipv4AddressRequiresReplace replaces a host only when it already has an IPv4
// address; a host without one gets it in place through the add-IP route.
func ipv4AddressRequiresReplace(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
	resp.RequiresReplace = !req.StateValue.IsNull()
}

// ipAddressesUseStateUnlessIPv4Added keeps ip_addresses known during plan.
// The list changes only when an IPv4 address is added to a host without one.
type ipAddressesUseStateUnlessIPv4Added struct{}

func (ipAddressesUseStateUnlessIPv4Added) Description(_ context.Context) string {
	return "Uses the prior ip_addresses unless an IPv4 address is being added."
}

func (m ipAddressesUseStateUnlessIPv4Added) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (ipAddressesUseStateUnlessIPv4Added) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	if req.StateValue.IsNull() || !req.PlanValue.IsUnknown() || req.ConfigValue.IsUnknown() {
		return
	}
	var configured, prior types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("ipv4_address"), &configured)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("ipv4_address"), &prior)...)
	if resp.Diagnostics.HasError() || (prior.IsNull() && !configured.IsNull()) {
		return
	}
	resp.PlanValue = req.StateValue
}

// enrollmentCodeUseStateUnlessReminted keeps the stored code unless a trigger
// change will mint a new one; then the code stays unknown so values derived
// from it, such as user data, change in the same apply. Terraform re-plans
// during apply with resolved values, so a trigger unknown at plan time could
// resolve equal to the stored map and quietly keep a consumed code after the
// dependent machine was already destroyed; such triggers are rejected instead.
type enrollmentCodeUseStateUnlessReminted struct{}

func (enrollmentCodeUseStateUnlessReminted) Description(_ context.Context) string {
	return "Uses the prior enrollment_code unless enrollment_code_triggers changes."
}

func (m enrollmentCodeUseStateUnlessReminted) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (enrollmentCodeUseStateUnlessReminted) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	if req.State.Raw.IsNull() || !req.PlanValue.IsUnknown() {
		return
	}
	var planTriggers, stateTriggers types.Map
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("enrollment_code_triggers"), &planTriggers)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("enrollment_code_triggers"), &stateTriggers)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if raw, err := planTriggers.ToTerraformValue(ctx); err != nil || !raw.IsFullyKnown() {
		resp.Diagnostics.AddAttributeError(path.Root("enrollment_code_triggers"), "Unknown enrollment_code_triggers",
			"The triggers of an existing host must be known at plan time, so the plan can say whether a new enrollment "+
				"code will be minted. Use values Terraform knows during plan, such as an AMI ID from a data source, or "+
				"apply the resources they depend on first.")
		return
	}
	if planTriggers.Equal(stateTriggers) {
		resp.PlanValue = req.StateValue
	}
}
