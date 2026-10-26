// Package provider implements the definednet Terraform provider.
package provider

import (
	"context"
	"errors"
	"net/http"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
)

const (
	envAPIKey   = "DEFINEDNET_API_KEY"
	envEndpoint = "DEFINEDNET_ENDPOINT"
)

var _ provider.Provider = (*definednetProvider)(nil)

type definednetProvider struct {
	version string
}

type providerModel struct {
	APIKey                    types.String `tfsdk:"api_key"`
	Endpoint                  types.String `tfsdk:"endpoint"`
	SkipCredentialsValidation types.Bool   `tfsdk:"skip_credentials_validation"`
}

// New returns a provider factory for the given build version.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &definednetProvider{version: version}
	}
}

func (p *definednetProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "definednet"
	resp.Version = p.version
}

func (p *definednetProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage Defined Networking networks, roles, tags, routes, SSO domains, and endpoint OIDC providers through the " +
			"[Defined Networking API](https://docs.defined.net/api/defined-networking-api/).\n\n" +
			"Create an API key at https://admin.defined.net/settings/api-keys with the scopes for the " +
			"resources you manage (for example `roles:create`, `roles:read`, `roles:update`, `roles:delete`).",
		Attributes: map[string]schema.Attribute{
			"api_key": schema.StringAttribute{
				MarkdownDescription: "API key used as the bearer token. Falls back to the `" + envAPIKey + "` environment variable.",
				Optional:            true,
				Sensitive:           true,
			},
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "Base URL of the API. Falls back to the `" + envEndpoint + "` environment variable, then `" + client.DefaultEndpoint + "`.",
				Optional:            true,
			},
			"skip_credentials_validation": schema.BoolAttribute{
				MarkdownDescription: "Skip the `GET /v2/whoami` check that verifies the API key when the provider is configured. Defaults to `false`.",
				Optional:            true,
			},
		},
	}
}

func (p *definednetProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if cfg.APIKey.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("api_key"), "Unknown API key",
			"The provider cannot be configured with an unknown api_key. Set it statically or via "+envAPIKey+".")
	}
	if cfg.Endpoint.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"), "Unknown endpoint",
			"The provider cannot be configured with an unknown endpoint.")
	}
	if cfg.SkipCredentialsValidation.IsUnknown() {
		resp.Diagnostics.AddAttributeError(path.Root("skip_credentials_validation"), "Unknown skip_credentials_validation",
			"The provider cannot be configured with an unknown skip_credentials_validation. Set it statically.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	apiKey := os.Getenv(envAPIKey)
	if !cfg.APIKey.IsNull() {
		apiKey = cfg.APIKey.ValueString()
	}
	endpoint := os.Getenv(envEndpoint)
	if !cfg.Endpoint.IsNull() {
		endpoint = cfg.Endpoint.ValueString()
	}

	if apiKey == "" {
		resp.Diagnostics.AddAttributeError(path.Root("api_key"), "Missing API key",
			"Set api_key in the provider block or export "+envAPIKey+".")
		return
	}

	ua := "terraform-provider-definednet/" + p.version
	if req.TerraformVersion != "" {
		ua += " terraform/" + req.TerraformVersion
	}
	c, err := client.New(endpoint, apiKey, client.WithUserAgent(ua))
	if err != nil {
		resp.Diagnostics.AddError("Unable to create API client", err.Error())
		return
	}

	// Fail at configure time so a bad key surfaces once, not as an error per
	// resource. The opt-out exists for offline plans and stubbed APIs.
	if !cfg.SkipCredentialsValidation.ValueBool() {
		if err := c.Whoami(ctx); err != nil {
			var apiErr *client.APIError
			if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized {
				resp.Diagnostics.AddAttributeError(path.Root("api_key"), "Invalid api_key",
					"The API rejected the key as invalid or revoked: "+err.Error())
			} else {
				// Not attributed to api_key: the usual cause is the endpoint or the network.
				resp.Diagnostics.AddError("Unable to verify API credentials", err.Error())
			}
			return
		}
	}

	resp.DataSourceData = c
	resp.ResourceData = c
}

func (p *definednetProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		newNetworkResource,
		newRoleResource,
		newTagResource,
		newRouteResource,
		newDomainResource,
		newDomainVerificationResource,
		newEndpointOIDCProviderResource,
	}
}

func (p *definednetProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		newNetworkDataSource,
		newRoleDataSource,
		newRouteDataSource,
		newTagDataSource,
	}
}

// clientFromProviderData extracts the configured client, reporting a
// diagnostic when the provider was not configured (e.g. during validation).
func clientFromProviderData(data any, diags *diag.Diagnostics) *client.Client {
	if data == nil {
		return nil
	}
	c, ok := data.(*client.Client)
	if !ok {
		diags.AddError("Unexpected provider data",
			"Expected *client.Client from the provider. This is a bug in the provider.")
		return nil
	}
	return c
}
