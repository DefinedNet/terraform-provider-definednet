package client

import (
	"encoding/json"
	"time"
)

// PortRange is an inclusive port range on a firewall rule.
type PortRange struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
}

// FirewallRule is an inbound firewall rule on a role, tag, or route. LocalCIDR
// is only meaningful for route rules and is omitted from role and tag requests.
type FirewallRule struct {
	Protocol      string     `json:"protocol"`
	Description   string     `json:"description"`
	AllowedRoleID *string    `json:"allowedRoleID"`
	AllowedTags   []string   `json:"allowedTags"`
	PortRange     *PortRange `json:"portRange"`
	LocalCIDR     string     `json:"localCIDR,omitempty"`
}

// Role is the API representation of a role.
type Role struct {
	ID            string         `json:"id"`
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	FirewallRules []FirewallRule `json:"firewallRules"`
	HostCount     int64          `json:"hostCount"`
	CreatedAt     time.Time      `json:"createdAt"`
	ModifiedAt    time.Time      `json:"modifiedAt"`
}

// RoleCreateRequest is the body of POST /v1/roles.
type RoleCreateRequest struct {
	Name          string         `json:"name"`
	Description   string         `json:"description"`
	FirewallRules []FirewallRule `json:"firewallRules"`
}

// RoleUpdateRequest is the body of PUT /v1/roles/{id}. The API does not allow
// renaming a role.
type RoleUpdateRequest struct {
	Description   string         `json:"description"`
	FirewallRules []FirewallRule `json:"firewallRules"`
}

// ConfigOverride is one nebula config override. Value is the raw JSON value
// so the provider never has to know the per-key type.
type ConfigOverride struct {
	Key   string          `json:"key"`
	Value json.RawMessage `json:"value"`
}

// Tag is the API representation of a tag. Tags are addressed by name.
type Tag struct {
	Name               string           `json:"name"`
	Description        string           `json:"description"`
	Priority           int64            `json:"priority"`
	HostCount          int64            `json:"hostCount"`
	ConfigOverrides    []ConfigOverride `json:"configOverrides"`
	RouteSubscriptions []string         `json:"routeSubscriptions"`
	FirewallRules      []FirewallRule   `json:"firewallRules"`
}

// TagCreateRequest is the body of POST /v1/tags.
type TagCreateRequest struct {
	Name               string           `json:"name"`
	Description        string           `json:"description"`
	Before             *string          `json:"before,omitempty"`
	After              *string          `json:"after,omitempty"`
	ConfigOverrides    []ConfigOverride `json:"configOverrides"`
	RouteSubscriptions []string         `json:"routeSubscriptions"`
	FirewallRules      []FirewallRule   `json:"firewallRules"`
}

// TagUpdateRequest is the body of PUT /v1/tags/{name}. FirewallRules must be
// non-nil: the API leaves rules untouched when the field is null.
type TagUpdateRequest struct {
	Description        string           `json:"description"`
	Before             *string          `json:"before,omitempty"`
	After              *string          `json:"after,omitempty"`
	ConfigOverrides    []ConfigOverride `json:"configOverrides"`
	RouteSubscriptions []string         `json:"routeSubscriptions"`
	FirewallRules      []FirewallRule   `json:"firewallRules"`
}

// RouteCIDR is the per-CIDR definition of a route.
type RouteCIDR struct {
	Install bool `json:"install"`
}

// Route is the API representation of a route.
type Route struct {
	ID            string               `json:"id"`
	Name          string               `json:"name"`
	Description   string               `json:"description"`
	RouterHostID  *string              `json:"routerHostID"`
	RoutableCIDRs map[string]RouteCIDR `json:"routableCIDRs"`
	FirewallRules []FirewallRule       `json:"firewallRules"`
	CreatedAt     time.Time            `json:"createdAt"`
	ModifiedAt    time.Time            `json:"modifiedAt"`
}

// RouteRequest is the body of both POST /v1/routes and PUT /v1/routes/{id}.
type RouteRequest struct {
	Name          string               `json:"name"`
	Description   string               `json:"description"`
	RouterHostID  *string              `json:"routerHostID"`
	RoutableCIDRs map[string]RouteCIDR `json:"routableCIDRs"`
	FirewallRules []FirewallRule       `json:"firewallRules"`
}

// Network is the v2 API representation of a network.
type Network struct {
	ID                        string    `json:"id"`
	OrganizationID            string    `json:"organizationID"`
	SigningCAID               string    `json:"signingCAID"`
	Name                      string    `json:"name"`
	Description               string    `json:"description"`
	CIDRs                     []string  `json:"cidrs"`
	CertVersion               int64     `json:"certVersion"`
	LighthousesAsRelays       bool      `json:"lighthousesAsRelays"`
	DisableManagedLighthouses bool      `json:"disableManagedLighthouses"`
	Curve                     string    `json:"curve"`
	HostCount                 int64     `json:"hostCount"`
	CreatedAt                 time.Time `json:"createdAt"`
}

// NetworkCreateRequest is the body of POST /v2/networks. CIDRs may hold at
// most one IPv4 prefix; the IPv6 prefix is always generated by the API.
type NetworkCreateRequest struct {
	Name                      string   `json:"name"`
	Description               string   `json:"description"`
	CIDRs                     []string `json:"cidrs"`
	LighthousesAsRelays       bool     `json:"lighthousesAsRelays"`
	DisableManagedLighthouses bool     `json:"disableManagedLighthouses"`
	Curve                     *string  `json:"curve,omitempty"`
}

// NetworkUpdateRequest is the body of PUT /v2/networks/{id}. PUT is a full
// replacement, so every field is always sent.
type NetworkUpdateRequest struct {
	Name                      string `json:"name"`
	Description               string `json:"description"`
	LighthousesAsRelays       bool   `json:"lighthousesAsRelays"`
	DisableManagedLighthouses bool   `json:"disableManagedLighthouses"`
}

// NetworkAddCIDRRequest is the body of POST /v2/networks/{id}/cidrs.
type NetworkAddCIDRRequest struct {
	CIDR string `json:"cidr"`
}

// ConfigOverridesBody is the body and response of GET and PUT
// /v1/networks/{id}/config-overrides. PUT replaces the whole list.
type ConfigOverridesBody struct {
	Overrides []ConfigOverride `json:"overrides"`
}

// Domain is the API representation of a domain. Zone and Value describe the
// TXT record that proves ownership: a record named Zone under DomainName
// holding Value. Both are derived from the domain and organization, so they
// never change for a given domain.
type Domain struct {
	ID         string `json:"id"`
	DomainName string `json:"domainName"`
	IsVerified bool   `json:"isVerified"`
	Zone       string `json:"zone"`
	Value      string `json:"value"`
}

// DomainCreateRequest is the body of POST /v1/domains. Domains cannot be
// renamed; the API has no update.
type DomainCreateRequest struct {
	DomainName string `json:"domainName"`
}
