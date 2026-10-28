package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// Whoami checks that the API key is accepted. GET /v2/whoami is open to any
// actor, so it needs no scope; the response body is not needed.
func (c *Client) Whoami(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodGet, "/v2/whoami", nil, nil, nil)
	return err
}

// Roles

func (c *Client) CreateRole(ctx context.Context, req RoleCreateRequest) (*Role, error) {
	var out Role
	if _, err := c.do(ctx, http.MethodPost, "/v1/roles", nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetRole(ctx context.Context, id string) (*Role, error) {
	var out Role
	if _, err := c.do(ctx, http.MethodGet, "/v1/roles/"+pathSegment(id), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) UpdateRole(ctx context.Context, id string, req RoleUpdateRequest) (*Role, error) {
	var out Role
	if _, err := c.do(ctx, http.MethodPut, "/v1/roles/"+pathSegment(id), nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteRole(ctx context.Context, id string) error {
	_, err := c.do(ctx, http.MethodDelete, "/v1/roles/"+pathSegment(id), nil, nil, nil)
	return err
}

// Tags

func (c *Client) CreateTag(ctx context.Context, req TagCreateRequest) (*Tag, error) {
	var out Tag
	if _, err := c.do(ctx, http.MethodPost, "/v1/tags", nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetTag(ctx context.Context, name string) (*Tag, error) {
	var out Tag
	if _, err := c.do(ctx, http.MethodGet, "/v1/tags/"+pathSegment(name), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) UpdateTag(ctx context.Context, name string, req TagUpdateRequest) (*Tag, error) {
	var out Tag
	if _, err := c.do(ctx, http.MethodPatch, "/v1/tags/"+pathSegment(name), nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteTag(ctx context.Context, name string) error {
	_, err := c.do(ctx, http.MethodDelete, "/v1/tags/"+pathSegment(name), nil, nil, nil)
	return err
}

// Routes

func (c *Client) CreateRoute(ctx context.Context, req RouteRequest) (*Route, error) {
	var out Route
	if _, err := c.do(ctx, http.MethodPost, "/v1/routes", nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetRoute(ctx context.Context, id string) (*Route, error) {
	var out Route
	if _, err := c.do(ctx, http.MethodGet, "/v1/routes/"+pathSegment(id), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) UpdateRoute(ctx context.Context, id string, req RouteRequest) (*Route, error) {
	var out Route
	if _, err := c.do(ctx, http.MethodPut, "/v1/routes/"+pathSegment(id), nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteRoute(ctx context.Context, id string) error {
	_, err := c.do(ctx, http.MethodDelete, "/v1/routes/"+pathSegment(id), nil, nil, nil)
	return err
}

// Networks

func (c *Client) CreateNetwork(ctx context.Context, req NetworkCreateRequest) (*Network, error) {
	var out Network
	if _, err := c.do(ctx, http.MethodPost, "/v2/networks", nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetNetwork(ctx context.Context, id string) (*Network, error) {
	var out Network
	if _, err := c.do(ctx, http.MethodGet, "/v2/networks/"+pathSegment(id), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) UpdateNetwork(ctx context.Context, id string, req NetworkUpdateRequest) (*Network, error) {
	var out Network
	if _, err := c.do(ctx, http.MethodPut, "/v2/networks/"+pathSegment(id), nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) AddNetworkCIDR(ctx context.Context, id string, cidr string) (*Network, error) {
	var out Network
	req := NetworkAddCIDRRequest{CIDR: cidr}
	if _, err := c.do(ctx, http.MethodPost, "/v2/networks/"+pathSegment(id)+"/cidrs", nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetNetworkConfigOverrides(ctx context.Context, id string) ([]ConfigOverride, error) {
	var out ConfigOverridesBody
	if _, err := c.do(ctx, http.MethodGet, "/v1/networks/"+pathSegment(id)+"/config-overrides", nil, nil, &out); err != nil {
		return nil, err
	}
	return out.Overrides, nil
}

func (c *Client) SetNetworkConfigOverrides(ctx context.Context, id string, overrides []ConfigOverride) ([]ConfigOverride, error) {
	var out ConfigOverridesBody
	req := ConfigOverridesBody{Overrides: overrides}
	if _, err := c.do(ctx, http.MethodPut, "/v1/networks/"+pathSegment(id)+"/config-overrides", nil, req, &out); err != nil {
		return nil, err
	}
	return out.Overrides, nil
}

func (c *Client) DeleteNetwork(ctx context.Context, id string) error {
	_, err := c.do(ctx, http.MethodDelete, "/v1/networks/"+pathSegment(id), nil, nil, nil)
	return err
}

// ListNetworks walks every page of GET /v2/networks.
func (c *Client) ListNetworks(ctx context.Context) ([]Network, error) {
	return listAll[Network](ctx, c, "/v2/networks")
}

// ListRoles walks every page of GET /v1/roles. List items omit firewall
// rules; call GetRole for the full object.
func (c *Client) ListRoles(ctx context.Context) ([]Role, error) {
	return listAll[Role](ctx, c, "/v1/roles")
}

// ListRoutes walks every page of GET /v1/routes. List items omit firewall
// rules; call GetRoute for the full object.
func (c *Client) ListRoutes(ctx context.Context) ([]Route, error) {
	return listAll[Route](ctx, c, "/v1/routes")
}

// ListTags walks every page of GET /v2/tags; /v1/tags has no list route.
func (c *Client) ListTags(ctx context.Context) ([]Tag, error) {
	return listAll[Tag](ctx, c, "/v2/tags")
}

func (c *Client) ListDomains(ctx context.Context) ([]Domain, error) {
	return listAll[Domain](ctx, c, "/v1/domains")
}

func (c *Client) ListEndpointOIDCProviders(ctx context.Context) ([]EndpointOIDCProvider, error) {
	return listAll[EndpointOIDCProvider](ctx, c, "/v1/endpoint-oidc-providers")
}

func listAll[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var all []T
	cursor := ""
	for {
		q := url.Values{"pageSize": {"500"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var page []T
		meta, err := c.do(ctx, http.MethodGet, path, q, nil, &page)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)

		var pm PaginationMetadata
		if len(meta) > 0 {
			if err := json.Unmarshal(meta, &pm); err != nil {
				return nil, err
			}
		}
		if !pm.HasNextPage || pm.NextCursor == "" {
			return all, nil
		}
		cursor = pm.NextCursor
	}
}

// Domains

func (c *Client) CreateDomain(ctx context.Context, req DomainCreateRequest) (*Domain, error) {
	var out Domain
	if _, err := c.do(ctx, http.MethodPost, "/v1/domains", nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetDomain(ctx context.Context, id string) (*Domain, error) {
	var out Domain
	if _, err := c.do(ctx, http.MethodGet, "/v1/domains/"+pathSegment(id), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteDomain(ctx context.Context, id string) error {
	_, err := c.do(ctx, http.MethodDelete, "/v1/domains/"+pathSegment(id), nil, nil, nil)
	return err
}

// VerifyDomain asks the API to look up the domain's TXT record. The lookup
// happens server-side, so a record that has not propagated yet fails with
// one of the ERR_DOMAIN_VERIFICATION_* codes rather than succeeding later.
func (c *Client) VerifyDomain(ctx context.Context, id string) error {
	_, err := c.do(ctx, http.MethodPost, "/v1/domains/"+pathSegment(id)+"/verify", nil, nil, nil)
	return err
}

// Endpoint OIDC providers

func (c *Client) CreateEndpointOIDCProvider(ctx context.Context, req EndpointOIDCProviderRequest) (*EndpointOIDCProvider, error) {
	var out EndpointOIDCProvider
	if _, err := c.do(ctx, http.MethodPost, "/v1/endpoint-oidc-providers", nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetEndpointOIDCProvider(ctx context.Context, id string) (*EndpointOIDCProvider, error) {
	var out EndpointOIDCProvider
	if _, err := c.do(ctx, http.MethodGet, "/v1/endpoint-oidc-providers/"+pathSegment(id), nil, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) UpdateEndpointOIDCProvider(ctx context.Context, id string, req EndpointOIDCProviderRequest) (*EndpointOIDCProvider, error) {
	var out EndpointOIDCProvider
	if _, err := c.do(ctx, http.MethodPut, "/v1/endpoint-oidc-providers/"+pathSegment(id), nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteEndpointOIDCProvider(ctx context.Context, id string) error {
	_, err := c.do(ctx, http.MethodDelete, "/v1/endpoint-oidc-providers/"+pathSegment(id), nil, nil, nil)
	return err
}
