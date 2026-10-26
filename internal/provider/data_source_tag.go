package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
)

var (
	_ datasource.DataSource              = (*tagDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*tagDataSource)(nil)
)

func newTagDataSource() datasource.DataSource { return &tagDataSource{} }

type tagDataSource struct {
	client *client.Client
}

// tagDataSourceModel is tagModel without before and after, which only exist
// as write-time positioning hints.
type tagDataSourceModel struct {
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	Priority           types.Int64  `tfsdk:"priority"`
	ConfigOverrides    types.Set    `tfsdk:"config_overrides"`
	RouteSubscriptions types.Set    `tfsdk:"route_subscriptions"`
	FirewallRules      types.Set    `tfsdk:"firewall_rules"`
}

func (d *tagDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tag"
}

func (d *tagDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up an existing tag by name.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Same as `name`; tags have no separate ID.",
				Computed:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Tag in `key:value` form.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(tagNameRegexp, "must be a key:value tag with no surrounding whitespace")},
			},
			"description": schema.StringAttribute{Computed: true, MarkdownDescription: "Tag description."},
			"priority":    schema.Int64Attribute{Computed: true, MarkdownDescription: "Precedence assigned by the API. Overrides from a higher priority win over lower ones."},
			"config_overrides": schema.SetNestedAttribute{
				Computed:            true,
				MarkdownDescription: "Nebula config overrides applied to hosts with this tag.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"key":   schema.StringAttribute{Computed: true, MarkdownDescription: "Dotted nebula config key, e.g. `lighthouse.dns.host`."},
						"value": schema.StringAttribute{Computed: true, CustomType: jsontypes.NormalizedType{}, MarkdownDescription: "JSON-encoded value for the key; use `jsondecode()` to read it."},
					},
				},
			},
			"route_subscriptions": schema.SetAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Route IDs every host with this tag is subscribed to."},
			"firewall_rules":      firewallRulesDataSchema(false, "Inbound firewall rules applied to hosts with this tag, in addition to their role's rules."),
		},
	}
}

func (d *tagDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *tagDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg tagDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	name := cfg.Name.ValueString()
	tag, err := d.client.GetTag(ctx, name)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read tag", fmt.Sprintf("tag %q: %s", name, err))
		return
	}

	rules, diags := flattenFirewallRules(ctx, tag.FirewallRules, false)
	resp.Diagnostics.Append(diags...)
	overrides, diags := flattenConfigOverrides(ctx, tag.ConfigOverrides, types.SetNull(configOverrideObjectType))
	resp.Diagnostics.Append(diags...)
	subs, diags := types.SetValueFrom(ctx, types.StringType, nonNilStrings(tag.RouteSubscriptions))
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	m := tagDataSourceModel{
		ID:                 types.StringValue(tag.Name),
		Name:               types.StringValue(tag.Name),
		Description:        types.StringValue(tag.Description),
		Priority:           types.Int64Value(tag.Priority),
		ConfigOverrides:    overrides,
		RouteSubscriptions: subs,
		FirewallRules:      rules,
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
