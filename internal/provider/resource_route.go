package provider

import (
	"context"
	"fmt"
	"net/netip"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
)

var (
	_ resource.Resource                   = (*routeResource)(nil)
	_ resource.ResourceWithConfigure      = (*routeResource)(nil)
	_ resource.ResourceWithImportState    = (*routeResource)(nil)
	_ resource.ResourceWithValidateConfig = (*routeResource)(nil)
)

func newRouteResource() resource.Resource { return &routeResource{} }

type routeResource struct {
	client *client.Client
}

type routeModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	Description   types.String `tfsdk:"description"`
	RouterHostID  types.String `tfsdk:"router_host_id"`
	RoutableCIDRs types.Map    `tfsdk:"routable_cidrs"`
	FirewallRules types.Set    `tfsdk:"firewall_rules"`
}

type routeCIDRModel struct {
	Install types.Bool `tfsdk:"install"`
}

var routeCIDRObjectType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"install": types.BoolType,
}}

func (r *routeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_route"
}

func (r *routeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a route: a set of IPv4 CIDRs reachable through a router host, with firewall rules " +
			"controlling which hosts may send traffic to them. Hosts are subscribed to a route through tags " +
			"(`definednet_tag.route_subscriptions`).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Route ID, e.g. `route-X47KHSCOSQJP5IOKNNKRRGHVAI`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Route name, 1-50 characters.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.UTF8LengthBetween(1, 50)},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Optional description, at most 255 characters.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
				Validators:          []validator.String{stringvalidator.UTF8LengthAtMost(255)},
			},
			"router_host_id": schema.StringAttribute{
				MarkdownDescription: "ID of the host that forwards traffic for this route. Omit to leave the route without a router.",
				Optional:            true,
			},
			"routable_cidrs": schema.MapNestedAttribute{
				MarkdownDescription: "IPv4 CIDRs reachable through the route, keyed by CIDR.",
				Optional:            true,
				Computed:            true,
				Default:             mapdefault.StaticValue(types.MapValueMust(routeCIDRObjectType, map[string]attr.Value{})),
				Validators: []validator.Map{
					mapvalidator.KeysAre(ipv4PrefixValidator{}),
				},
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"install": schema.BoolAttribute{
							MarkdownDescription: "Install the route into the subscribed host's kernel routing table.",
							Optional:            true,
							Computed:            true,
							Default:             booldefault.StaticBool(false),
						},
					},
				},
			},
			"firewall_rules": firewallRulesSchema(true, "Firewall rules for traffic entering the routed CIDRs. Each rule's `local_cidr` must overlap one of `routable_cidrs`."),
		},
	}
}

// ValidateConfig mirrors the API rule that each firewall rule's local_cidr
// must overlap a routable CIDR. Prefixes either nest or are disjoint, so
// overlapping means one contains the other.
func (r *routeResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg routeModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() || cfg.RoutableCIDRs.IsUnknown() || cfg.FirewallRules.IsNull() || cfg.FirewallRules.IsUnknown() {
		return
	}

	var routable []netip.Prefix
	for cidr := range cfg.RoutableCIDRs.Elements() {
		if p, err := netip.ParsePrefix(cidr); err == nil {
			routable = append(routable, p)
		}
	}

	var rules []routeFirewallRuleModel
	resp.Diagnostics.Append(cfg.FirewallRules.ElementsAs(ctx, &rules, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for _, rule := range rules {
		if rule.LocalCIDR.IsNull() || rule.LocalCIDR.IsUnknown() || rule.LocalCIDR.ValueString() == "ANY" {
			continue
		}
		p, err := netip.ParsePrefix(rule.LocalCIDR.ValueString())
		if err != nil {
			continue // reported by the attribute validator
		}
		overlaps := slices.ContainsFunc(routable, func(rp netip.Prefix) bool {
			return prefixContains(rp, p) || prefixContains(p, rp)
		})
		if !overlaps {
			resp.Diagnostics.AddAttributeError(path.Root("firewall_rules"), "Invalid local_cidr",
				fmt.Sprintf("local_cidr %q must overlap one of routable_cidrs.", rule.LocalCIDR.ValueString()))
		}
	}
}

func (r *routeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *routeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan routeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body, diags := r.expand(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	route, err := r.client.CreateRoute(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create route", fmt.Sprintf("route %q: %s", plan.Name.ValueString(), describeError(err)))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, route, &resp.State)...)
}

func (r *routeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state routeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	route, err := r.client.GetRoute(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read route", fmt.Sprintf("route %q: %s", state.ID.ValueString(), err))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, route, &resp.State)...)
}

func (r *routeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan routeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body, diags := r.expand(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	route, err := r.client.UpdateRoute(ctx, plan.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("Unable to update route", fmt.Sprintf("route %q: %s", plan.ID.ValueString(), err))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, route, &resp.State)...)
}

func (r *routeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state routeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteRoute(ctx, state.ID.ValueString())
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete route", fmt.Sprintf("route %q: %s", state.ID.ValueString(), describeError(err)))
	}
}

func (r *routeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *routeResource) expand(ctx context.Context, plan routeModel) (client.RouteRequest, diag.Diagnostics) {
	var diags diag.Diagnostics
	body := client.RouteRequest{
		Name:          plan.Name.ValueString(),
		Description:   plan.Description.ValueString(),
		RouterHostID:  optionalString(plan.RouterHostID),
		RoutableCIDRs: map[string]client.RouteCIDR{},
	}

	if !plan.RoutableCIDRs.IsNull() && !plan.RoutableCIDRs.IsUnknown() {
		var cidrs map[string]routeCIDRModel
		diags.Append(plan.RoutableCIDRs.ElementsAs(ctx, &cidrs, false)...)
		for cidr, def := range cidrs {
			body.RoutableCIDRs[cidr] = client.RouteCIDR{Install: def.Install.ValueBool()}
		}
	}

	rules, d := expandFirewallRules(ctx, plan.FirewallRules, true)
	diags.Append(d...)
	body.FirewallRules = rules
	return body, diags
}

func (r *routeResource) setState(ctx context.Context, route *client.Route, state stateSetter) diag.Diagnostics {
	m, diags := flattenRoute(ctx, route)
	if diags.HasError() {
		return diags
	}
	diags.Append(state.Set(ctx, &m)...)
	return diags
}

func flattenRoute(ctx context.Context, route *client.Route) (routeModel, diag.Diagnostics) {
	rules, diags := flattenFirewallRules(ctx, route.FirewallRules, true)

	cidrElems := make(map[string]attr.Value, len(route.RoutableCIDRs))
	for cidr, def := range route.RoutableCIDRs {
		obj, d := types.ObjectValue(routeCIDRObjectType.AttrTypes, map[string]attr.Value{
			"install": types.BoolValue(def.Install),
		})
		diags.Append(d...)
		cidrElems[cidr] = obj
	}
	cidrs, d := types.MapValue(routeCIDRObjectType, cidrElems)
	diags.Append(d...)

	return routeModel{
		ID:            types.StringValue(route.ID),
		Name:          types.StringValue(route.Name),
		Description:   types.StringValue(route.Description),
		RouterHostID:  types.StringPointerValue(route.RouterHostID),
		RoutableCIDRs: cidrs,
		FirewallRules: rules,
	}, diags
}
