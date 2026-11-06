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

// TagUpdateRequest is the body of PATCH /v1/tags/{name}. PATCH leaves absent
// fields untouched, so every managed field is always sent; null clears, same as
// an empty value. Before and After are move commands, omitted to stay in place.
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

// EndpointOIDCProvider is the API representation of an endpoint SSO provider.
// The client secret is never returned. AutoAssignCIDRs is what the server
// stored, which may include prefixes the network forces on every host.
type EndpointOIDCProvider struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	ClientID          string   `json:"clientID"`
	IssuerURL         string   `json:"issuerURL"`
	Enabled           bool     `json:"enabled"`
	NetworkID         string   `json:"networkID"`
	RoleID            *string  `json:"roleID"`
	AuthValidityHours *int64   `json:"authValidityHours"`
	DomainID          *string  `json:"domainID"`
	AutoAssignCIDRs   []string `json:"autoAssignCIDRs"`
}

// EndpointOIDCProviderRequest is the body of POST /v1/endpoint-oidc-providers
// and PUT /v1/endpoint-oidc-providers/{id}. PUT is a full replacement except
// that a null ClientSecret keeps the stored secret.
type EndpointOIDCProviderRequest struct {
	Name              string   `json:"name"`
	ClientID          string   `json:"clientID"`
	ClientSecret      *string  `json:"clientSecret"`
	IssuerURL         string   `json:"issuerURL"`
	Enabled           bool     `json:"enabled"`
	NetworkID         string   `json:"networkID"`
	RoleID            *string  `json:"roleID"`
	AuthValidityHours *int64   `json:"authValidityHours"`
	DomainID          *string  `json:"domainID"`
	AutoAssignCIDRs   []string `json:"autoAssignCIDRs"`
}

// JoinKey is the API representation of a join key: a reusable credential that
// creates a host with the key's shape on every enrollment. The shape
// (network, role, tags, prefixes) cannot change after creation.
// AutoAssignCIDRs is what the server stored, which includes the network's
// IPv6 prefix and, on certificate version 1 networks, its IPv4 prefix.
type JoinKey struct {
	ID              string     `json:"id"`
	Name            string     `json:"name"`
	NetworkID       string     `json:"networkID"`
	RoleID          *string    `json:"roleID"`
	Tags            []string   `json:"tags"`
	AutoAssignCIDRs []string   `json:"autoAssignCIDRs"`
	ExpiresAt       *time.Time `json:"expiresAt"`
}

// JoinKeyCreateResponse is the response of POST /v1/join-keys, the only one
// that carries the token.
type JoinKeyCreateResponse struct {
	JoinKey
	Token string `json:"token"`
}

// JoinKeyCreateRequest is the body of POST /v1/join-keys. A nil
// AutoAssignCIDRs lets the API choose the network's default.
type JoinKeyCreateRequest struct {
	Name            string     `json:"name"`
	NetworkID       string     `json:"networkID"`
	RoleID          *string    `json:"roleID"`
	Tags            []string   `json:"tags"`
	AutoAssignCIDRs []string   `json:"autoAssignCIDRs"`
	ExpiresAt       *time.Time `json:"expiresAt"`
}

// JoinKeyPatchRequest is the body of PATCH /v1/join-keys/{id}. A nil field is
// omitted, which leaves it unchanged; ExpiresAt pointing at a nil time sends
// null, which removes the expiry.
type JoinKeyPatchRequest struct {
	Name      *string     `json:"name,omitempty"`
	ExpiresAt **time.Time `json:"expiresAt,omitempty"`
}

// Host is the v2 API representation of a host. IPAddresses holds at most one
// address per family, IPv4 first.
type Host struct {
	ID              string           `json:"id"`
	NetworkID       string           `json:"networkID"`
	RoleID          *string          `json:"roleID"`
	Name            string           `json:"name"`
	IPAddresses     []string         `json:"ipAddresses"`
	StaticAddresses []string         `json:"staticAddresses"`
	ListenPort      int64            `json:"listenPort"`
	IsLighthouse    bool             `json:"isLighthouse"`
	IsRelay         bool             `json:"isRelay"`
	IsBlocked       bool             `json:"isBlocked"`
	Tags            []string         `json:"tags"`
	ConfigOverrides []ConfigOverride `json:"configOverrides"`
}

// HostCreateRequest is the body of POST /v2/hosts. IPAddresses takes an
// explicit address or the network's own prefix per family; a prefix asks the
// API to assign the next free address from it. IPv6 is assigned either way.
type HostCreateRequest struct {
	NetworkID       string           `json:"networkID"`
	RoleID          *string          `json:"roleID"`
	Name            string           `json:"name"`
	IPAddresses     []string         `json:"ipAddresses"`
	StaticAddresses []string         `json:"staticAddresses"`
	ListenPort      int64            `json:"listenPort"`
	IsLighthouse    bool             `json:"isLighthouse"`
	IsRelay         bool             `json:"isRelay"`
	Tags            []string         `json:"tags"`
	ConfigOverrides []ConfigOverride `json:"configOverrides"`
}

// HostUpdateRequest is the body of PUT /v3/hosts/{id}, a full replacement of
// the fields a host can change after creation.
type HostUpdateRequest struct {
	Name            string           `json:"name"`
	RoleID          *string          `json:"roleID"`
	StaticAddresses []string         `json:"staticAddresses"`
	ListenPort      int64            `json:"listenPort"`
	Tags            []string         `json:"tags"`
	ConfigOverrides []ConfigOverride `json:"configOverrides"`
}

// HostAddIPRequest is the body of POST /v2/hosts/{id}/ip-addresses: an IPv4
// address, or the network's IPv4 prefix to assign the next free address.
type HostAddIPRequest struct {
	IPAddress string `json:"ipAddress"`
}

// HostAndEnrollmentCodeCreateRequest is the body of POST /v2/host-and-enrollment-code.
// A nil CodeLifetimeSeconds takes the API default of one day.
type HostAndEnrollmentCodeCreateRequest struct {
	HostCreateRequest
	CodeLifetimeSeconds *int64 `json:"codeLifetimeSeconds"`
}

// HostAndEnrollmentCode is the response of POST /v2/host-and-enrollment-code.
type HostAndEnrollmentCode struct {
	Host           Host           `json:"host"`
	EnrollmentCode EnrollmentCode `json:"enrollmentCode"`
}

// EnrollmentCodeRequest is the body of POST /v1/hosts/{id}/enrollment-code.
// A nil LifetimeSeconds takes the API default of one day.
type EnrollmentCodeRequest struct {
	LifetimeSeconds *int64 `json:"lifetimeSeconds"`
}

// EnrollmentCode is a single-use code that binds the first key pair to redeem
// it to an existing host.
type EnrollmentCode struct {
	Code            string `json:"code"`
	LifetimeSeconds int64  `json:"lifetimeSeconds"`
}
