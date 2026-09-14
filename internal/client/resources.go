package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

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
	if _, err := c.do(ctx, http.MethodPut, "/v1/tags/"+pathSegment(name), nil, req, &out); err != nil {
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

func (c *Client) DeleteNetwork(ctx context.Context, id string) error {
	_, err := c.do(ctx, http.MethodDelete, "/v1/networks/"+pathSegment(id), nil, nil, nil)
	return err
}

// ListNetworks walks every page of GET /v2/networks.
func (c *Client) ListNetworks(ctx context.Context) ([]Network, error) {
	var all []Network
	cursor := ""
	for {
		q := url.Values{"pageSize": {"500"}}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var page []Network
		meta, err := c.do(ctx, http.MethodGet, "/v2/networks", q, nil, &page)
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
