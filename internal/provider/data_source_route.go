package provider

import (
	"context"
	"fmt"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
)

var (
	_ datasource.DataSource                     = (*routeDataSource)(nil)
	_ datasource.DataSourceWithConfigure        = (*routeDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*routeDataSource)(nil)
)

func newRouteDataSource() datasource.DataSource { return &routeDataSource{} }

type routeDataSource struct {
	client *client.Client
}

func (d *routeDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_route"
}

func (d *routeDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up an existing route by ID or by exact name.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Route ID. Exactly one of `id` or `name` must be set.",
				Optional:            true,
				Computed:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Exact route name. Exactly one of `id` or `name` must be set.",
				Optional:            true,
				Computed:            true,
			},
			"description":    schema.StringAttribute{Computed: true, MarkdownDescription: "Route description."},
			"router_host_id": schema.StringAttribute{Computed: true, MarkdownDescription: "ID of the host that forwards traffic for this route, if any."},
			"routable_cidrs": schema.MapNestedAttribute{
				Computed:            true,
				MarkdownDescription: "IPv4 CIDRs reachable through the route, keyed by CIDR.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"install": schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether subscribed hosts install the route into their kernel routing table."},
					},
				},
			},
			"firewall_rules": firewallRulesDataSchema(true, "Firewall rules for traffic entering the routed CIDRs. Each rule's `local_cidr` overlaps one of `routable_cidrs`."),
		},
	}
}

func (d *routeDataSource) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(path.MatchRoot("id"), path.MatchRoot("name")),
	}
}

func (d *routeDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *routeDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg routeModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := cfg.ID.ValueString()
	if cfg.ID.IsNull() {
		name := cfg.Name.ValueString()
		all, err := d.client.ListRoutes(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to list routes", err.Error())
			return
		}
		// Route names are unique within an organization.
		i := slices.IndexFunc(all, func(r client.Route) bool { return r.Name == name })
		if i < 0 {
			resp.Diagnostics.AddError("Route not found", fmt.Sprintf("No route is named %q.", name))
			return
		}
		id = all[i].ID
	}

	// List items omit firewall rules, so always fetch the full object.
	route, err := d.client.GetRoute(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read route", fmt.Sprintf("route %q: %s", id, err))
		return
	}

	m, diags := flattenRoute(ctx, route)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
