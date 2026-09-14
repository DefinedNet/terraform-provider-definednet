package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
)

var (
	_ datasource.DataSource                     = (*networkDataSource)(nil)
	_ datasource.DataSourceWithConfigure        = (*networkDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*networkDataSource)(nil)
)

func newNetworkDataSource() datasource.DataSource { return &networkDataSource{} }

type networkDataSource struct {
	client *client.Client
}

func (d *networkDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network"
}

func (d *networkDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Looks up an existing network by ID or by exact name.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Network ID. Exactly one of `id` or `name` must be set.",
				Optional:            true,
				Computed:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Exact network name. Exactly one of `id` or `name` must be set.",
				Optional:            true,
				Computed:            true,
			},
			"description":                 schema.StringAttribute{Computed: true, MarkdownDescription: "Network description."},
			"ipv4_cidr":                   schema.StringAttribute{Computed: true, MarkdownDescription: "The network's IPv4 prefix, if it has one."},
			"cidrs":                       schema.ListAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: "Every prefix assigned to the network."},
			"cert_version":                schema.Int64Attribute{Computed: true, MarkdownDescription: "Nebula certificate version in use."},
			"curve":                       schema.StringAttribute{Computed: true, MarkdownDescription: "Certificate curve: `25519` or `P256`."},
			"lighthouses_as_relays":       schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether lighthouses act as relays."},
			"disable_managed_lighthouses": schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether the network has opted out of the managed lighthouse."},
			"organization_id":             schema.StringAttribute{Computed: true, MarkdownDescription: "ID of the owning organization."},
			"signing_ca_id":               schema.StringAttribute{Computed: true, MarkdownDescription: "ID of the signing certificate authority."},
			"created_at":                  schema.StringAttribute{Computed: true, MarkdownDescription: "Creation timestamp in RFC 3339 form."},
		},
	}
}

func (d *networkDataSource) ConfigValidators(_ context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{
		datasourcevalidator.ExactlyOneOf(path.MatchRoot("id"), path.MatchRoot("name")),
	}
}

func (d *networkDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *networkDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg networkModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var network *client.Network
	if !cfg.ID.IsNull() {
		n, err := d.client.GetNetwork(ctx, cfg.ID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Unable to read network", err.Error())
			return
		}
		network = n
	} else {
		name := cfg.Name.ValueString()
		all, err := d.client.ListNetworks(ctx)
		if err != nil {
			resp.Diagnostics.AddError("Unable to list networks", err.Error())
			return
		}
		var matches []client.Network
		for _, n := range all {
			if n.Name == name {
				matches = append(matches, n)
			}
		}
		switch len(matches) {
		case 0:
			resp.Diagnostics.AddError("Network not found", fmt.Sprintf("No network is named %q.", name))
			return
		case 1:
			network = &matches[0]
		default:
			resp.Diagnostics.AddError("Multiple networks match",
				fmt.Sprintf("%d networks are named %q; look the network up by id instead.", len(matches), name))
			return
		}
	}

	m, diags := flattenNetwork(ctx, network)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
