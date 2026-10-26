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
	_ datasource.DataSource                     = (*roleDataSource)(nil)
	_ datasource.DataSourceWithConfigure        = (*roleDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*roleDataSource)(nil)
)

func newRoleDataSource() datasource.DataSource { return &roleDataSource{} }

type roleDataSource struct {
	client *client.Client
}

func (d *roleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func (d *roleDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up an existing role by ID or by exact name.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Role ID. Exactly one of `id` or `name` must be set.",
				Optional:            true,
				Computed:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Exact role name. Exactly one of `id` or `name` must be set.",
				Optional:            true,
				Computed:            true,
			},
			"description":    schema.StringAttribute{Computed: true, MarkdownDescription: "Role description."},
			"firewall_rules": firewallRulesDataSchema(false, "Inbound firewall rules applied to hosts with this role."),
		},
	}
}

func (d *roleDataSource) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(path.MatchRoot("id"), path.MatchRoot("name")),
	}
}

func (d *roleDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *roleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg roleModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := cfg.ID.ValueString()
	if cfg.ID.IsNull() {
		name := cfg.Name.ValueString()
		all, err := d.client.ListRoles(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to list roles", err.Error())
			return
		}
		// Role names are unique within an organization.
		i := slices.IndexFunc(all, func(r client.Role) bool { return r.Name == name })
		if i < 0 {
			resp.Diagnostics.AddError("Role not found", fmt.Sprintf("No role is named %q.", name))
			return
		}
		id = all[i].ID
	}

	// List items omit firewall rules, so always fetch the full object.
	role, err := d.client.GetRole(ctx, id)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read role", fmt.Sprintf("role %q: %s", id, err))
		return
	}

	m, diags := flattenRole(ctx, role)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
