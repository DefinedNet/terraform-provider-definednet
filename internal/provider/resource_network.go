package provider

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
)

var (
	_ resource.Resource                = (*networkResource)(nil)
	_ resource.ResourceWithConfigure   = (*networkResource)(nil)
	_ resource.ResourceWithImportState = (*networkResource)(nil)
)

func newNetworkResource() resource.Resource { return &networkResource{} }

type networkResource struct {
	client *client.Client
}

type networkModel struct {
	ID                        types.String `tfsdk:"id"`
	Name                      types.String `tfsdk:"name"`
	Description               types.String `tfsdk:"description"`
	IPv4CIDR                  types.String `tfsdk:"ipv4_cidr"`
	CIDRs                     types.List   `tfsdk:"cidrs"`
	CertVersion               types.Int64  `tfsdk:"cert_version"`
	Curve                     types.String `tfsdk:"curve"`
	LighthousesAsRelays       types.Bool   `tfsdk:"lighthouses_as_relays"`
	DisableManagedLighthouses types.Bool   `tfsdk:"disable_managed_lighthouses"`
	OrganizationID            types.String `tfsdk:"organization_id"`
	SigningCAID               types.String `tfsdk:"signing_ca_id"`
	CreatedAt                 types.String `tfsdk:"created_at"`
}

func (r *networkResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network"
}

func (r *networkResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a network. The API key needs the `networks:create`, `networks:read`, " +
			"`networks:update`, and `networks:delete` scopes.\n\n" +
			"A network must have no hosts before it can be deleted.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Network ID, e.g. `network-ZJOW3QUQUX5ZAVPVYRHDQUAEIY`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Network name, 1-255 characters.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthBetween(1, 255)},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Optional description.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
			},
			"ipv4_cidr": schema.StringAttribute{
				MarkdownDescription: "IPv4 prefix for the network, e.g. `100.100.0.0/22`: /8 to /30, inside private or CGNAT space. Omit for an IPv6-only network. " +
					"An IPv4 prefix can be added to an existing IPv6-only network, but once set it cannot be changed or removed " +
					"without replacing the network.",
				Optional:   true,
				Validators: []validator.String{ipv4PrefixValidator{minBits: 8, maxBits: 30, private: true}},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplaceIf(ipv4CIDRRequiresReplace,
						"Changing or removing an existing IPv4 CIDR requires a new network.",
						"Changing or removing an existing IPv4 CIDR requires a new network."),
				},
			},
			"cidrs": schema.ListAttribute{
				MarkdownDescription: "Every prefix assigned to the network. IPv6-capable networks always include a generated IPv6 prefix.",
				Computed:            true,
				ElementType:         types.StringType,
				PlanModifiers:       []planmodifier.List{cidrsUseStateUnlessIPv4Changes{}},
			},
			"cert_version": schema.Int64Attribute{
				MarkdownDescription: "Nebula certificate version in use. Version 2 is required for IPv6.",
				Computed:            true,
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"curve": schema.StringAttribute{
				MarkdownDescription: "Certificate curve: `25519` or `P256`. Defaults to the API's choice. Changing it forces a new network.",
				Optional:            true,
				Computed:            true,
				Validators:          []validator.String{stringvalidator.OneOf("25519", "P256")},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"lighthouses_as_relays": schema.BoolAttribute{
				MarkdownDescription: "Configure the network's lighthouses, managed or self-hosted, as relays for hosts that cannot connect directly.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"disable_managed_lighthouses": schema.BoolAttribute{
				MarkdownDescription: "Opt out of the managed lighthouse. Only set this if you run your own lighthouses. No effect on cert version 1 networks.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(false),
			},
			"organization_id": schema.StringAttribute{
				MarkdownDescription: "ID of the owning organization.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"signing_ca_id": schema.StringAttribute{
				MarkdownDescription: "ID of the certificate authority signing host certificates for this network.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"created_at": schema.StringAttribute{
				MarkdownDescription: "Creation timestamp in RFC 3339 form.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

// ipv4CIDRRequiresReplace forces replacement only when a network that already
// has an IPv4 prefix is asked for a different one (or none); going from no
// prefix to a prefix is handled in place through the add-CIDR endpoint.
func ipv4CIDRRequiresReplace(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
	if req.StateValue.IsNull() || req.StateValue.IsUnknown() {
		return
	}
	if req.PlanValue.IsUnknown() {
		return
	}
	resp.RequiresReplace = !req.PlanValue.Equal(req.StateValue)
}

// cidrsUseStateUnlessIPv4Changes keeps cidrs known during plan. The list only
// changes when ipv4_cidr does; the IPv6 prefix is fixed at creation.
type cidrsUseStateUnlessIPv4Changes struct{}

func (cidrsUseStateUnlessIPv4Changes) Description(_ context.Context) string {
	return "Uses the prior cidrs unless ipv4_cidr changes."
}

func (m cidrsUseStateUnlessIPv4Changes) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (cidrsUseStateUnlessIPv4Changes) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	if req.StateValue.IsNull() || !req.PlanValue.IsUnknown() || req.ConfigValue.IsUnknown() {
		return
	}
	var planned, prior types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("ipv4_cidr"), &planned)...)
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root("ipv4_cidr"), &prior)...)
	if resp.Diagnostics.HasError() || !planned.Equal(prior) {
		return
	}
	resp.PlanValue = req.StateValue
}

func (r *networkResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *networkResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan networkModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := client.NetworkCreateRequest{
		Name:                      plan.Name.ValueString(),
		Description:               plan.Description.ValueString(),
		CIDRs:                     []string{},
		LighthousesAsRelays:       plan.LighthousesAsRelays.ValueBool(),
		DisableManagedLighthouses: plan.DisableManagedLighthouses.ValueBool(),
		Curve:                     optionalString(plan.Curve),
	}
	if !plan.IPv4CIDR.IsNull() {
		body.CIDRs = append(body.CIDRs, plan.IPv4CIDR.ValueString())
	}

	network, err := r.client.CreateNetwork(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create network", fmt.Sprintf("network %q: %s", plan.Name.ValueString(), err))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, network, &resp.State)...)
}

func (r *networkResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state networkModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	network, err := r.client.GetNetwork(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read network", fmt.Sprintf("network %q: %s", state.ID.ValueString(), err))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, network, &resp.State)...)
}

func (r *networkResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state networkModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := plan.ID.ValueString()
	network, err := r.client.UpdateNetwork(ctx, id, client.NetworkUpdateRequest{
		Name:                      plan.Name.ValueString(),
		Description:               plan.Description.ValueString(),
		LighthousesAsRelays:       plan.LighthousesAsRelays.ValueBool(),
		DisableManagedLighthouses: plan.DisableManagedLighthouses.ValueBool(),
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to update network", fmt.Sprintf("network %q: %s", id, err))
		return
	}

	// The plan modifier only lets ipv4_cidr change from null to a value in
	// place; any other change replaces the network.
	if state.IPv4CIDR.IsNull() && !plan.IPv4CIDR.IsNull() {
		network, err = r.client.AddNetworkCIDR(ctx, id, plan.IPv4CIDR.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Unable to add IPv4 CIDR to network", fmt.Sprintf("network %q: %s", id, err))
			return
		}
	}

	resp.Diagnostics.Append(r.setState(ctx, network, &resp.State)...)
}

func (r *networkResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state networkModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteNetwork(ctx, state.ID.ValueString())
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete network", fmt.Sprintf("network %q: %s", state.ID.ValueString(), err))
	}
}

func (r *networkResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *networkResource) setState(ctx context.Context, n *client.Network, state stateSetter) diag.Diagnostics {
	m, diags := flattenNetwork(ctx, n)
	if diags.HasError() {
		return diags
	}
	diags.Append(state.Set(ctx, &m)...)
	return diags
}

// flattenNetwork builds the Terraform model shared by the resource and data source.
func flattenNetwork(ctx context.Context, n *client.Network) (networkModel, diag.Diagnostics) {
	cidrs, diags := types.ListValueFrom(ctx, types.StringType, nonNilStrings(n.CIDRs))

	ipv4 := types.StringNull()
	for _, c := range n.CIDRs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Addr().Is4() {
			ipv4 = types.StringValue(c)
			break
		}
	}

	return networkModel{
		ID:                        types.StringValue(n.ID),
		Name:                      types.StringValue(n.Name),
		Description:               types.StringValue(n.Description),
		IPv4CIDR:                  ipv4,
		CIDRs:                     cidrs,
		CertVersion:               types.Int64Value(n.CertVersion),
		Curve:                     types.StringValue(n.Curve),
		LighthousesAsRelays:       types.BoolValue(n.LighthousesAsRelays),
		DisableManagedLighthouses: types.BoolValue(n.DisableManagedLighthouses),
		OrganizationID:            types.StringValue(n.OrganizationID),
		SigningCAID:               types.StringValue(n.SigningCAID),
		CreatedAt:                 types.StringValue(n.CreatedAt.UTC().Format("2006-01-02T15:04:05Z07:00")),
	}, diags
}
