package provider

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

// fakeAPI is an in-memory stand-in for api.defined.net that reproduces the
// behaviors the provider has to cope with: firewall rules come back sorted by
// CIDR and port rather than submission order, empty tag sets serialize as
// null, config override values are re-formatted, and tag priorities are
// assigned server-side. missingScopes lists permissions the key lacks so
// scope errors can be exercised.
type fakeAPI struct {
	mu            sync.Mutex
	apiKey        string
	missingScopes map[string]bool

	roles    map[string]*client.Role
	tags     map[string]*client.Tag
	routes   map[string]*client.Route
	networks map[string]*client.Network
	domains  map[string]*client.Domain
	oidc     map[string]*client.EndpointOIDCProvider
	// oidcSecrets holds each provider's current client secret; oidcSecretPuts
	// records the clientSecret of every PUT (nil when the body sent null).
	oidcSecrets    map[string]string
	oidcSecretPuts map[string][]*string
	// domainVerifyFailures is how many verify calls still fail with
	// domainVerifyFailCode (NXDOMAIN when empty), standing in for a TXT
	// record that has not propagated yet.
	domainVerifyFailures   int
	domainVerifyFailCode   string
	domainVerifyFailStatus int

	// tagUpdates holds the last PATCH body received for each tag.
	tagUpdates map[string]client.TagUpdateRequest
	// networkOverrides and networkOverridePuts hold each network's config
	// overrides and how many times they were PUT.
	networkOverrides    map[string][]client.ConfigOverride
	networkOverridePuts map[string]int
	// rolePuts counts PUTs per role.
	rolePuts map[string]int

	joinKeys map[string]*client.JoinKey
	// joinKeyPatches holds the raw body of every join key PATCH.
	joinKeyPatches []string
	// joinKeysDisabled stands in for an organization without the JOIN_KEYS
	// feature flag, where every join key route is a 404.
	joinKeysDisabled bool
	hosts            map[string]*client.Host
	// enrollmentCodes holds every code minted per host, in order.
	enrollmentCodes map[string][]client.EnrollmentCode
	// hostPuts counts PUTs per host.
	hostPuts map[string]int

	server *httptest.Server
}

func newFakeAPI() *fakeAPI {
	f := &fakeAPI{
		apiKey:              "test-key",
		roles:               map[string]*client.Role{},
		tags:                map[string]*client.Tag{},
		routes:              map[string]*client.Route{},
		networks:            map[string]*client.Network{},
		domains:             map[string]*client.Domain{},
		oidc:                map[string]*client.EndpointOIDCProvider{},
		oidcSecrets:         map[string]string{},
		oidcSecretPuts:      map[string][]*string{},
		tagUpdates:          map[string]client.TagUpdateRequest{},
		networkOverrides:    map[string][]client.ConfigOverride{},
		networkOverridePuts: map[string]int{},
		rolePuts:            map[string]int{},
		joinKeys:            map[string]*client.JoinKey{},
		hosts:               map[string]*client.Host{},
		enrollmentCodes:     map[string][]client.EnrollmentCode{},
		hostPuts:            map[string]int{},
	}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	return f
}

func (f *fakeAPI) Close() { f.server.Close() }

func (f *fakeAPI) URL() string { return f.server.URL }

func newID(prefix string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return prefix + "-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeData(w http.ResponseWriter, v any) {
	writeJSON(w, http.StatusOK, map[string]any{"data": v, "metadata": map[string]any{}})
}

func writeErr(w http.ResponseWriter, status int, code, msg, path string) {
	e := map[string]any{"code": code, "message": msg}
	if path != "" {
		e["path"] = path
	}
	writeJSON(w, status, map[string]any{"errors": []any{e}})
}

func notFound(w http.ResponseWriter) {
	writeErr(w, http.StatusNotFound, "ERR_NOT_FOUND", "resource not found", "")
}

func decode(r *http.Request, v any) error {
	return json.NewDecoder(r.Body).Decode(v)
}

// normalizeRules mimics the API: rules are stored unordered and returned
// sorted by local CIDR then from-port, and empty tag lists become null.
func normalizeRules(rules []client.FirewallRule) []client.FirewallRule {
	out := make([]client.FirewallRule, 0, len(rules))
	for _, r := range rules {
		if len(r.AllowedTags) == 0 {
			r.AllowedTags = nil
		}
		out = append(out, r)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].LocalCIDR != out[j].LocalCIDR {
			return out[i].LocalCIDR < out[j].LocalCIDR
		}
		var pi, pj int64
		if out[i].PortRange != nil {
			pi = out[i].PortRange.From
		}
		if out[j].PortRange != nil {
			pj = out[j].PortRange.From
		}
		return pi < pj
	})
	return out
}

// reformatJSON simulates the database re-serializing JSON values with
// different whitespace than the client sent and, for objects, keys in an
// order other than the sorted one jsonencode() produces.
func reformatJSON(raw json.RawMessage) json.RawMessage {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err == nil && obj != nil {
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
		var buf bytes.Buffer
		buf.WriteString("{")
		for i, k := range keys {
			if i > 0 {
				buf.WriteString(", ")
			}
			kb, _ := json.Marshal(k)
			buf.Write(kb)
			buf.WriteString(": ")
			buf.Write(reformatJSON(obj[k]))
		}
		buf.WriteString("}")
		return buf.Bytes()
	}
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return raw
	}
	return buf.Bytes()
}

func (f *fakeAPI) handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Request-ID", newID("req"))
	if r.Header.Get("Authorization") != "Bearer "+f.apiKey {
		writeErr(w, http.StatusUnauthorized, "ERR_UNAUTHORIZED", "unauthorized", "")
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	switch {
	case len(parts) == 2 && parts[0] == "v2" && parts[1] == "whoami" && r.Method == http.MethodGet:
		writeData(w, map[string]any{"actorType": "apiKey", "actor": map[string]any{}, "organization": map[string]any{"id": "org-TEST"}})
	case len(parts) >= 2 && parts[0] == "v1" && parts[1] == "roles":
		f.handleRoles(w, r, parts[2:])
	case len(parts) >= 2 && parts[0] == "v1" && parts[1] == "tags":
		f.handleTags(w, r, parts[2:])
	case len(parts) >= 2 && parts[0] == "v1" && parts[1] == "routes":
		f.handleRoutes(w, r, parts[2:])
	case len(parts) >= 2 && parts[1] == "networks":
		f.handleNetworks(w, r, parts[0], parts[2:])
	case len(parts) >= 2 && parts[0] == "v1" && parts[1] == "domains":
		f.handleDomains(w, r, parts[2:])
	case len(parts) >= 2 && parts[0] == "v1" && parts[1] == "endpoint-oidc-providers":
		f.handleOIDCProviders(w, r, parts[2:])
	case len(parts) >= 2 && parts[0] == "v1" && parts[1] == "join-keys" && !f.joinKeysDisabled:
		f.handleJoinKeys(w, r, parts[2:])
	case len(parts) >= 2 && parts[1] == "hosts":
		f.handleHosts(w, r, parts[0], parts[2:])
	case len(parts) == 2 && parts[0] == "v2" && parts[1] == "host-and-enrollment-code" && r.Method == http.MethodPost:
		var req client.HostAndEnrollmentCodeCreateRequest
		if err := decode(r, &req); err != nil {
			writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
			return
		}
		h, ok := f.createHost(w, req.HostCreateRequest)
		if !ok {
			return
		}
		code, ok := f.mintEnrollmentCode(w, h, req.CodeLifetimeSeconds)
		if !ok {
			delete(f.hosts, h.ID)
			return
		}
		writeData(w, client.HostAndEnrollmentCode{Host: *h, EnrollmentCode: code})
	default:
		notFound(w)
	}
}

func (f *fakeAPI) handleRoles(w http.ResponseWriter, r *http.Request, rest []string) {
	switch {
	case len(rest) == 0 && r.Method == http.MethodGet:
		writePage(w, r, f.roles, func(role client.Role) any {
			role.FirewallRules = nil
			return role
		})

	case len(rest) == 0 && r.Method == http.MethodPost:
		var req client.RoleCreateRequest
		if err := decode(r, &req); err != nil {
			writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
			return
		}
		for _, existing := range f.roles {
			if existing.Name == req.Name {
				writeErr(w, 400, "ERR_DUPLICATE_VALUE", "value already exists", "name")
				return
			}
		}
		if !f.validRoleRefs(w, req.FirewallRules) {
			return
		}
		now := time.Now().UTC().Truncate(time.Second)
		role := &client.Role{
			ID: newID("role"), Name: req.Name, Description: req.Description,
			FirewallRules: normalizeRules(req.FirewallRules), CreatedAt: now, ModifiedAt: now,
		}
		f.roles[role.ID] = role
		writeData(w, role)

	case len(rest) == 1:
		role, ok := f.roles[rest[0]]
		if !ok {
			notFound(w)
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeData(w, role)
		case http.MethodPut:
			var req client.RoleUpdateRequest
			if err := decode(r, &req); err != nil {
				writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
				return
			}
			if !f.validRoleRefs(w, req.FirewallRules) {
				return
			}
			f.rolePuts[role.ID]++
			role.Description = req.Description
			role.FirewallRules = normalizeRules(req.FirewallRules)
			role.ModifiedAt = time.Now().UTC().Truncate(time.Second)
			writeData(w, role)
		case http.MethodDelete:
			delete(f.roles, rest[0])
			writeData(w, map[string]any{})
		default:
			writeErr(w, 405, "ERR_METHOD_NOT_ALLOWED", "method not allowed", "")
		}
	default:
		notFound(w)
	}
}

// validRoleRefs mimics the API refusing an allowedRoleID that is not an
// existing role, which is what makes a placeholder such as "self" unsendable.
func (f *fakeAPI) validRoleRefs(w http.ResponseWriter, rules []client.FirewallRule) bool {
	for _, rule := range rules {
		if rule.AllowedRoleID == nil {
			continue
		}
		if _, ok := f.roles[*rule.AllowedRoleID]; !ok {
			writeErr(w, 400, "ERR_INVALID_REFERENCE", "referenced value is invalid", "firewallRules")
			return false
		}
	}
	return true
}

// placeTag assigns a priority. New tags go on top (max+1) unless before or
// after positions them; existing tags are shifted to make room.
func (f *fakeAPI) placeTag(tag *client.Tag, before, after *string) error {
	if before != nil && after != nil {
		return fmt.Errorf("may only set before or after, not both")
	}
	if before == nil && after == nil {
		if tag.Priority != 0 {
			return nil
		}
		max := int64(0)
		for _, t := range f.tags {
			if t.Priority > max {
				max = t.Priority
			}
		}
		tag.Priority = max + 1
		return nil
	}

	var target int64
	if before != nil {
		t, ok := f.tags[*before]
		if !ok {
			return fmt.Errorf("before: referenced value is invalid")
		}
		target = t.Priority
	} else {
		t, ok := f.tags[*after]
		if !ok {
			return fmt.Errorf("after: referenced value is invalid")
		}
		target = t.Priority + 1
	}
	for _, t := range f.tags {
		if t != tag && t.Priority >= target {
			t.Priority++
		}
	}
	tag.Priority = target
	return nil
}

func (f *fakeAPI) handleTags(w http.ResponseWriter, r *http.Request, rest []string) {
	switch {
	case len(rest) == 0 && r.Method == http.MethodPost:
		var req client.TagCreateRequest
		if err := decode(r, &req); err != nil {
			writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
			return
		}
		if _, exists := f.tags[req.Name]; exists {
			writeErr(w, 400, "ERR_DUPLICATE_VALUE", "value already exists", "name")
			return
		}
		tag := &client.Tag{Name: req.Name}
		f.applyTag(tag, req.Description, req.ConfigOverrides, req.RouteSubscriptions, req.FirewallRules)
		if err := f.placeTag(tag, req.Before, req.After); err != nil {
			writeErr(w, 400, "ERR_INVALID_REFERENCE", err.Error(), "before")
			return
		}
		f.tags[tag.Name] = tag
		writeData(w, tag)

	case len(rest) == 1:
		tag, ok := f.tags[rest[0]]
		if !ok {
			notFound(w)
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeData(w, tag)
		case http.MethodPatch:
			var raw json.RawMessage
			var req client.TagUpdateRequest
			var present map[string]json.RawMessage
			err := decode(r, &raw)
			if err == nil {
				err = json.Unmarshal(raw, &req)
			}
			if err == nil {
				err = json.Unmarshal(raw, &present)
			}
			if err != nil {
				writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
				return
			}
			f.tagUpdates[tag.Name] = req
			// Absent fields are untouched; a present one (null included) replaces.
			if _, ok := present["description"]; ok {
				tag.Description = req.Description
			}
			if _, ok := present["configOverrides"]; ok {
				tag.ConfigOverrides = storeOverrides(req.ConfigOverrides)
			}
			if _, ok := present["routeSubscriptions"]; ok {
				tag.RouteSubscriptions = nonNilStrings(req.RouteSubscriptions)
			}
			if _, ok := present["firewallRules"]; ok {
				tag.FirewallRules = normalizeRules(req.FirewallRules)
			}
			if err := f.placeTag(tag, req.Before, req.After); err != nil {
				writeErr(w, 400, "ERR_INVALID_REFERENCE", err.Error(), "before")
				return
			}
			writeData(w, tag)
		case http.MethodDelete:
			delete(f.tags, rest[0])
			writeData(w, map[string]any{})
		default:
			writeErr(w, 405, "ERR_METHOD_NOT_ALLOWED", "method not allowed", "")
		}
	default:
		notFound(w)
	}
}

func (f *fakeAPI) applyTag(tag *client.Tag, desc string, overrides []client.ConfigOverride, subs []string, rules []client.FirewallRule) {
	tag.Description = desc
	tag.ConfigOverrides = storeOverrides(overrides)
	tag.RouteSubscriptions = subs
	if tag.RouteSubscriptions == nil {
		tag.RouteSubscriptions = []string{}
	}
	tag.FirewallRules = normalizeRules(rules)
}

// storeOverrides mimics the API re-formatting values and returning overrides
// in reverse submission order.
func storeOverrides(overrides []client.ConfigOverride) []client.ConfigOverride {
	out := []client.ConfigOverride{}
	for _, o := range overrides {
		out = append(out, client.ConfigOverride{Key: o.Key, Value: reformatJSON(o.Value)})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Key > out[j].Key })
	return out
}

func (f *fakeAPI) handleRoutes(w http.ResponseWriter, r *http.Request, rest []string) {
	switch {
	case len(rest) == 0 && r.Method == http.MethodGet:
		writePage(w, r, f.routes, func(route client.Route) any {
			route.FirewallRules = nil
			return route
		})

	case len(rest) == 0 && r.Method == http.MethodPost:
		var req client.RouteRequest
		if err := decode(r, &req); err != nil {
			writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
			return
		}
		now := time.Now().UTC().Truncate(time.Second)
		route := &client.Route{ID: newID("route"), CreatedAt: now, ModifiedAt: now}
		applyRoute(route, req)
		f.routes[route.ID] = route
		writeData(w, route)

	case len(rest) == 1:
		route, ok := f.routes[rest[0]]
		if !ok {
			notFound(w)
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeData(w, route)
		case http.MethodPut:
			var req client.RouteRequest
			if err := decode(r, &req); err != nil {
				writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
				return
			}
			applyRoute(route, req)
			route.ModifiedAt = time.Now().UTC().Truncate(time.Second)
			writeData(w, route)
		case http.MethodDelete:
			delete(f.routes, rest[0])
			writeData(w, map[string]any{})
		default:
			writeErr(w, 405, "ERR_METHOD_NOT_ALLOWED", "method not allowed", "")
		}
	default:
		notFound(w)
	}
}

func applyRoute(route *client.Route, req client.RouteRequest) {
	route.Name = req.Name
	route.Description = req.Description
	route.RouterHostID = req.RouterHostID
	route.RoutableCIDRs = req.RoutableCIDRs
	if route.RoutableCIDRs == nil {
		route.RoutableCIDRs = map[string]client.RouteCIDR{}
	}
	route.FirewallRules = normalizeRules(req.FirewallRules)
}

// writePage serves one page of items sorted by key, using the offset-cursor
// scheme of the real API's responses. project mirrors the API returning list
// items that are summaries of the full object.
func writePage[T any](w http.ResponseWriter, r *http.Request, items map[string]*T, project func(T) any) {
	ids := make([]string, 0, len(items))
	for id := range items {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	pageSize := 25
	if ps := r.URL.Query().Get("pageSize"); ps != "" {
		pageSize, _ = strconv.Atoi(ps)
	}
	start := 0
	if c := r.URL.Query().Get("cursor"); c != "" {
		start, _ = strconv.Atoi(c)
	}
	end := start + pageSize
	if end > len(ids) {
		end = len(ids)
	}
	page := []any{}
	for _, id := range ids[start:end] {
		page = append(page, project(*items[id]))
	}
	meta := map[string]any{"hasNextPage": end < len(ids), "hasPrevPage": start > 0}
	if end < len(ids) {
		meta["nextCursor"] = strconv.Itoa(end)
	}
	writeJSON(w, 200, map[string]any{"data": page, "metadata": meta})
}

// addCertV1Network stores an IPv4-only certificate version 1 network, which
// the API no longer creates, and returns its ID.
func (f *fakeAPI) addCertV1Network(cidr string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := &client.Network{ID: newID("network"), OrganizationID: "org-TEST", Name: "v1", CIDRs: []string{cidr}, CertVersion: 1, Curve: "25519"}
	f.networks[n.ID] = n
	return n.ID
}

func (f *fakeAPI) handleNetworks(w http.ResponseWriter, r *http.Request, version string, rest []string) {
	switch {
	case version == "v2" && len(rest) == 0 && r.Method == http.MethodGet:
		writePage(w, r, f.networks, func(n client.Network) any { return n })

	case version == "v2" && len(rest) == 0 && r.Method == http.MethodPost:
		if f.missingScopes["networks:create"] {
			writeErr(w, http.StatusForbidden, "ERR_FORBIDDEN", "api key must support the following scopes: networks:create", "")
			return
		}
		var req client.NetworkCreateRequest
		if err := decode(r, &req); err != nil {
			writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
			return
		}
		curve := "25519"
		if req.Curve != nil {
			curve = *req.Curve
		}
		n := &client.Network{
			ID: newID("network"), OrganizationID: "org-TEST", SigningCAID: "ca-TEST",
			Name: req.Name, Description: req.Description,
			CIDRs:               append([]string{}, req.CIDRs...),
			CertVersion:         2,
			LighthousesAsRelays: req.LighthousesAsRelays, DisableManagedLighthouses: req.DisableManagedLighthouses,
			Curve:     curve,
			CreatedAt: time.Now().UTC().Truncate(time.Second),
		}
		n.CIDRs = append(n.CIDRs, "fd00:1234:5678:1::/80")
		f.networks[n.ID] = n
		// The real API seeds every new network with a generated tun.dev override.
		f.networkOverrides[n.ID] = []client.ConfigOverride{{Key: "tun.dev", Value: json.RawMessage(`"dn-` + n.ID[len(n.ID)-6:] + `"`)}}
		writeData(w, n)

	case len(rest) >= 1:
		n, ok := f.networks[rest[0]]
		if !ok {
			notFound(w)
			return
		}
		switch {
		case version == "v2" && len(rest) == 1 && r.Method == http.MethodGet:
			if f.missingScopes["networks:read"] {
				writeErr(w, http.StatusForbidden, "ERR_FORBIDDEN", "api key must support the following scopes: networks:read", "")
				return
			}
			writeData(w, n)
		case version == "v2" && len(rest) == 1 && r.Method == http.MethodPut:
			var req client.NetworkUpdateRequest
			if err := decode(r, &req); err != nil {
				writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
				return
			}
			n.Name, n.Description = req.Name, req.Description
			n.LighthousesAsRelays, n.DisableManagedLighthouses = req.LighthousesAsRelays, req.DisableManagedLighthouses
			writeData(w, n)
		case version == "v2" && len(rest) == 2 && rest[1] == "cidrs" && r.Method == http.MethodPost:
			var req client.NetworkAddCIDRRequest
			if err := decode(r, &req); err != nil {
				writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
				return
			}
			for _, c := range n.CIDRs {
				if !strings.Contains(c, ":") {
					writeErr(w, 400, "ERR_NETWORK_ALREADY_HAS_IPV4_CIDR", "network already has an IPv4 CIDR", "")
					return
				}
			}
			n.CIDRs = append([]string{req.CIDR}, n.CIDRs...)
			writeData(w, n)
		case version == "v1" && len(rest) == 2 && rest[1] == "config-overrides" && r.Method == http.MethodGet:
			writeData(w, client.ConfigOverridesBody{Overrides: f.networkOverrides[n.ID]})
		case version == "v1" && len(rest) == 2 && rest[1] == "config-overrides" && r.Method == http.MethodPut:
			var req client.ConfigOverridesBody
			if err := decode(r, &req); err != nil {
				writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
				return
			}
			f.networkOverridePuts[n.ID]++
			f.networkOverrides[n.ID] = storeOverrides(req.Overrides)
			writeData(w, client.ConfigOverridesBody{Overrides: f.networkOverrides[n.ID]})
		case version == "v1" && len(rest) == 1 && r.Method == http.MethodDelete:
			delete(f.networks, rest[0])
			delete(f.networkOverrides, rest[0])
			writeData(w, map[string]any{})
		default:
			notFound(w)
		}
	default:
		notFound(w)
	}
}

func (f *fakeAPI) handleDomains(w http.ResponseWriter, r *http.Request, rest []string) {
	switch {
	case len(rest) == 0 && r.Method == http.MethodPost:
		var req client.DomainCreateRequest
		if err := decode(r, &req); err != nil {
			writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
			return
		}
		name := strings.ToLower(req.DomainName)
		for _, existing := range f.domains {
			if existing.DomainName == name {
				writeErr(w, 400, "ERR_DUPLICATE_VALUE", "value already exists", "domainName")
				return
			}
		}
		d := &client.Domain{
			ID: newID("domain"), DomainName: name,
			Zone: "_defined_" + strings.ToLower(newID("")[1:9]), Value: newID("") + "=",
		}
		f.domains[d.ID] = d
		writeData(w, d)

	case len(rest) >= 1:
		d, ok := f.domains[rest[0]]
		if !ok {
			notFound(w)
			return
		}
		switch {
		case len(rest) == 1 && r.Method == http.MethodGet:
			writeData(w, d)
		case len(rest) == 1 && r.Method == http.MethodDelete:
			delete(f.domains, rest[0])
			writeData(w, map[string]any{})
		case len(rest) == 2 && rest[1] == "verify" && r.Method == http.MethodPost:
			if f.domainVerifyFailures > 0 {
				f.domainVerifyFailures--
				code := f.domainVerifyFailCode
				if code == "" {
					code = "ERR_DOMAIN_VERIFICATION_FAILED_NXDOMAIN"
				}
				status := f.domainVerifyFailStatus
				if status == 0 {
					status = 400
				}
				writeErr(w, status, code, "verification failed", "")
				return
			}
			d.IsVerified = true
			writeData(w, map[string]any{})
		default:
			writeErr(w, 405, "ERR_METHOD_NOT_ALLOWED", "method not allowed", "")
		}
	default:
		notFound(w)
	}
}

// recordAutoAssignCIDRs mimics the API's db layer: an IPv4-only (v1) network
// forces its own CIDR, and the network's IPv6 prefix is appended when missing.
func recordAutoAssignCIDRs(n *client.Network, cidrs []string) []string {
	var v4, v6 string
	for _, c := range n.CIDRs {
		if strings.Contains(c, ":") {
			v6 = c
		} else {
			v4 = c
		}
	}
	if n.CertVersion == 1 && v4 != "" {
		cidrs = []string{v4}
	}
	if v6 != "" {
		sent := false
		for _, c := range cidrs {
			if strings.Contains(c, ":") {
				sent = true
			}
		}
		if !sent {
			cidrs = append(cidrs, v6)
		}
	}
	return cidrs
}

// applyOIDC validates and stores a create or update body, returning false after
// writing the API's error.
func (f *fakeAPI) applyOIDC(w http.ResponseWriter, p *client.EndpointOIDCProvider, req client.EndpointOIDCProviderRequest) bool {
	if req.Enabled && req.DomainID == nil {
		writeErr(w, 400, "ERR_MISSING_VALUE", "domainID must be set if enabled is true", "domainID")
		return false
	}
	for _, other := range f.oidc {
		if other != p && other.Name == req.Name {
			writeErr(w, 400, "ERR_DUPLICATE_VALUE", "value already exists", "name")
			return false
		}
	}
	n, ok := f.networks[req.NetworkID]
	if !ok {
		writeErr(w, 400, "ERR_INVALID_REFERENCE", "referenced value is invalid", "networkID")
		return false
	}
	if req.RoleID != nil {
		if _, ok := f.roles[*req.RoleID]; !ok {
			writeErr(w, 400, "ERR_INVALID_REFERENCE", "referenced value is invalid", "roleID")
			return false
		}
	}
	if req.DomainID != nil {
		d, ok := f.domains[*req.DomainID]
		if !ok {
			writeErr(w, 400, "ERR_INVALID_REFERENCE", "referenced value is invalid", "domainID")
			return false
		}
		if req.Enabled && !d.IsVerified {
			writeErr(w, 400, "ERR_DOMAIN_NOT_VERIFIED", "cannot create an enabled endpoint OIDC provider without a verified domain", "domainID")
			return false
		}
		if req.Enabled {
			for _, other := range f.oidc {
				if other != p && other.Enabled && other.DomainID != nil && *other.DomainID == *req.DomainID {
					writeErr(w, 400, "ERR_DOMAIN_ALREADY_ENABLED", "domain already has an enabled provider", "domainID")
					return false
				}
			}
		}
	}
	if !validAutoAssign(w, n, req.AutoAssignCIDRs) {
		return false
	}
	p.Name, p.ClientID, p.IssuerURL, p.Enabled = req.Name, req.ClientID, req.IssuerURL, req.Enabled
	p.NetworkID, p.RoleID, p.AuthValidityHours, p.DomainID = req.NetworkID, req.RoleID, req.AuthValidityHours, req.DomainID
	p.AutoAssignCIDRs = recordAutoAssignCIDRs(n, req.AutoAssignCIDRs)
	return true
}

func (f *fakeAPI) handleOIDCProviders(w http.ResponseWriter, r *http.Request, rest []string) {
	switch {
	case len(rest) == 0 && r.Method == http.MethodPost:
		var req client.EndpointOIDCProviderRequest
		if err := decode(r, &req); err != nil {
			writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
			return
		}
		if req.ClientSecret == nil || *req.ClientSecret == "" {
			writeErr(w, 400, "ERR_INVALID_VALUE_LENGTH", "must be between 1 and 255", "clientSecret")
			return
		}
		p := &client.EndpointOIDCProvider{ID: newID("endpointoidc")}
		if !f.applyOIDC(w, p, req) {
			return
		}
		f.oidc[p.ID] = p
		f.oidcSecrets[p.ID] = *req.ClientSecret
		writeData(w, p)

	case len(rest) == 1:
		p, ok := f.oidc[rest[0]]
		if !ok {
			notFound(w)
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeData(w, p)
		case http.MethodPut:
			var req client.EndpointOIDCProviderRequest
			if err := decode(r, &req); err != nil {
				writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
				return
			}
			if !f.applyOIDC(w, p, req) {
				return
			}
			f.oidcSecretPuts[p.ID] = append(f.oidcSecretPuts[p.ID], req.ClientSecret)
			if req.ClientSecret != nil {
				f.oidcSecrets[p.ID] = *req.ClientSecret
			}
			writeData(w, p)
		case http.MethodDelete:
			delete(f.oidc, rest[0])
			writeData(w, map[string]any{})
		default:
			writeErr(w, 405, "ERR_METHOD_NOT_ALLOWED", "method not allowed", "")
		}
	default:
		notFound(w)
	}
}

// joinKeyNameRE is the API's rule, kept apart from the provider's own
// validator so a mistake in that validator still reaches the fake.
var joinKeyNameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// validAutoAssign mimics the API accepting only the network's own prefixes,
// compared as parsed prefixes so alternate spellings of the same prefix pass.
// An explicit empty list (sent as [], decoded non-nil) declines IPv4, which a
// v1 network cannot honor; a null or omitted list accepts the network's policy.
func validAutoAssign(w http.ResponseWriter, n *client.Network, cidrs []string) bool {
	if cidrs != nil && len(cidrs) == 0 && n.CertVersion == 1 {
		writeErr(w, 400, "ERR_INVALID_VALUE", "a certificate version 1 network assigns every host an IPv4 address", "autoAssignCIDRs")
		return false
	}
	for i, c := range cidrs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil || !slices.ContainsFunc(n.CIDRs, func(nc string) bool { return netip.MustParsePrefix(nc) == pfx }) {
			writeErr(w, 400, "ERR_OUT_OF_RANGE", "CIDR prefix does not match the network's prefix", fmt.Sprintf("autoAssignCIDRs[%d]", i))
			return false
		}
	}
	return true
}

func (f *fakeAPI) validJoinKeyName(w http.ResponseWriter, k *client.JoinKey, name string) bool {
	if len(name) < 1 || len(name) > 54 || !joinKeyNameRE.MatchString(name) {
		writeErr(w, 400, "ERR_INVALID_VALUE", "must contain only lowercase letters, digits, and hyphens", "name")
		return false
	}
	for _, other := range f.joinKeys {
		if other != k && other.Name == name {
			writeErr(w, 400, "ERR_DUPLICATE_VALUE", "value already exists", "name")
			return false
		}
	}
	return true
}

// validExpiry also stores t in UTC, the zone the API always answers in.
func validExpiry(w http.ResponseWriter, t *time.Time) bool {
	if t != nil {
		*t = t.UTC()
	}
	if t != nil && !t.After(time.Now()) {
		writeErr(w, 400, "ERR_INVALID_VALUE", "must be in the future", "expiresAt")
		return false
	}
	return true
}

func (f *fakeAPI) handleJoinKeys(w http.ResponseWriter, r *http.Request, rest []string) {
	switch {
	case len(rest) == 0 && r.Method == http.MethodGet:
		writePage(w, r, f.joinKeys, func(k client.JoinKey) any { return k })

	case len(rest) == 0 && r.Method == http.MethodPost:
		var req client.JoinKeyCreateRequest
		if err := decode(r, &req); err != nil {
			writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
			return
		}
		if !f.validJoinKeyName(w, nil, req.Name) || !validExpiry(w, req.ExpiresAt) {
			return
		}
		n, ok := f.networks[req.NetworkID]
		if !ok {
			writeErr(w, 400, "ERR_INVALID_REFERENCE", "referenced value is invalid", "networkID")
			return
		}
		if req.RoleID != nil {
			if _, ok := f.roles[*req.RoleID]; !ok {
				writeErr(w, 400, "ERR_INVALID_REFERENCE", "referenced value is invalid", "roleID")
				return
			}
		}
		if !validAutoAssign(w, n, req.AutoAssignCIDRs) {
			return
		}
		k := &client.JoinKey{
			ID: newID("dnjoin"), Name: req.Name, NetworkID: req.NetworkID, RoleID: req.RoleID,
			Tags: nonNilStrings(req.Tags), AutoAssignCIDRs: recordAutoAssignCIDRs(n, req.AutoAssignCIDRs),
			ExpiresAt: req.ExpiresAt,
		}
		f.joinKeys[k.ID] = k
		writeData(w, client.JoinKeyCreateResponse{JoinKey: *k, Token: k.ID + "-" + newID("")[1:]})

	case len(rest) == 1:
		k, ok := f.joinKeys[rest[0]]
		if !ok {
			notFound(w)
			return
		}
		switch r.Method {
		case http.MethodGet:
			writeData(w, k)
		case http.MethodPatch:
			var raw map[string]json.RawMessage
			if err := decode(r, &raw); err != nil {
				writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
				return
			}
			body, _ := json.Marshal(raw)
			f.joinKeyPatches = append(f.joinKeyPatches, string(body))
			name := k.Name
			if v, ok := raw["name"]; ok {
				if err := json.Unmarshal(v, &name); err != nil || string(v) == "null" {
					writeErr(w, 400, "ERR_MISSING_VALUE", "value is required", "name")
					return
				}
			}
			// An omitted expiry is kept unvalidated, so an expired key can still be renamed.
			expires := k.ExpiresAt
			if v, ok := raw["expiresAt"]; ok {
				expires = nil
				if err := json.Unmarshal(v, &expires); err != nil {
					writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "expiresAt")
					return
				}
				if !validExpiry(w, expires) {
					return
				}
			}
			if !f.validJoinKeyName(w, k, name) {
				return
			}
			k.Name, k.ExpiresAt = name, expires
			writeData(w, k)
		case http.MethodDelete:
			delete(f.joinKeys, rest[0])
			writeData(w, map[string]any{})
		default:
			writeErr(w, 405, "ERR_METHOD_NOT_ALLOWED", "method not allowed", "")
		}
	default:
		notFound(w)
	}
}

// validHostShape mirrors the API's Bind checks on lighthouse and relay hosts
// and on the fields every host write carries.
func (f *fakeAPI) validHostShape(w http.ResponseWriter, h *client.Host, name string, roleID *string, static []string, port int64, lighthouse, relay bool) bool {
	switch {
	case lighthouse && relay:
		writeErr(w, 400, "ERR_INVALID_VALUE", "lighthouse hosts must not also be relay hosts", "")
	case lighthouse && len(static) == 0:
		writeErr(w, 400, "ERR_INVALID_VALUE", "lighthouse hosts must have at least one static ip address", "staticAddresses")
	case (lighthouse || relay) && port == 0:
		writeErr(w, 400, "ERR_INVALID_VALUE", "lighthouse and relay hosts must specify a static (non-zero) listen port", "listenPort")
	case name == "" || strings.EqualFold(name, "any"):
		writeErr(w, 400, "ERR_INVALID_VALUE", "invalid name", "name")
	default:
		if roleID != nil {
			if _, ok := f.roles[*roleID]; !ok {
				writeErr(w, 400, "ERR_INVALID_REFERENCE", "referenced value is invalid", "roleID")
				return false
			}
		}
		for _, other := range f.hosts {
			if other != h && other.Name == name && (h == nil || other.NetworkID == h.NetworkID) {
				writeErr(w, 400, "ERR_DUPLICATE_VALUE", "value already exists", "name")
				return false
			}
		}
		return true
	}
	return false
}

// applyHost stores the mutable fields the way the API returns them: static
// addresses de-duplicated in order, tags sorted, overrides reformatted.
func applyHost(h *client.Host, name string, roleID *string, static []string, port int64, tags []string, overrides []client.ConfigOverride) {
	h.Name, h.RoleID, h.ListenPort = name, roleID, port
	h.StaticAddresses = []string{}
	for _, a := range static {
		if !slices.Contains(h.StaticAddresses, a) {
			h.StaticAddresses = append(h.StaticAddresses, a)
		}
	}
	h.Tags = slices.Sorted(slices.Values(nonNilStrings(tags)))
	h.ConfigOverrides = storeOverrides(overrides)
}

// assignHostIPs mimics createHost: an IPv4 address is assigned on a
// certificate version 1 network, or when the request names one or the
// network's IPv4 prefix; IPv6 is always assigned on a network that has it.
func (f *fakeAPI) assignHostIPs(w http.ResponseWriter, n *client.Network, req []string) ([]string, bool) {
	var v4, v6 netip.Prefix
	for _, c := range n.CIDRs {
		p := netip.MustParsePrefix(c)
		if p.Addr().Is4() {
			v4 = p
		} else {
			v6 = p
		}
	}
	taken := map[netip.Addr]bool{}
	for _, h := range f.hosts {
		if h.NetworkID == n.ID {
			for _, a := range h.IPAddresses {
				taken[netip.MustParseAddr(a)] = true
			}
		}
	}
	var ip4, ip6 netip.Addr
	auto4 := n.CertVersion == 1
	for i, s := range req {
		path := fmt.Sprintf("ipAddresses[%d]", i)
		if p, err := netip.ParsePrefix(s); err == nil {
			if p != v4 && p != v6 {
				writeErr(w, 400, "ERR_OUT_OF_RANGE", "CIDR prefix does not match the network's prefix", path)
				return nil, false
			}
			auto4 = auto4 || p == v4
			continue
		}
		a, err := netip.ParseAddr(s)
		// The API does not assign a prefix's network address, nor the IPv4 broadcast address.
		in4 := v4.Contains(a) && a != v4.Masked().Addr() && v4.Contains(a.Next())
		in6 := v6.Contains(a) && a != v6.Masked().Addr()
		if err != nil || (!in4 && !in6) {
			writeErr(w, 400, "ERR_OUT_OF_RANGE", "value is out of range", path)
			return nil, false
		}
		if taken[a] {
			writeErr(w, 400, "ERR_DUPLICATE_VALUE", "value already exists", path)
			return nil, false
		}
		if a.Is4() {
			ip4 = a
		} else {
			ip6 = a
		}
	}
	if !ip4.IsValid() && auto4 && v4.IsValid() {
		for a := v4.Addr().Next(); v4.Contains(a); a = a.Next() {
			if !taken[a] {
				ip4 = a
				break
			}
		}
	}
	if !ip6.IsValid() && v6.IsValid() {
		ip6 = v6.Addr().Next()
		for taken[ip6] {
			ip6 = ip6.Next()
		}
	}
	out := []string{}
	for _, a := range []netip.Addr{ip4, ip6} {
		if a.IsValid() {
			out = append(out, a.String())
		}
	}
	return out, true
}

func (f *fakeAPI) handleHosts(w http.ResponseWriter, r *http.Request, version string, rest []string) {
	switch {
	case version == "v2" && len(rest) == 0 && r.Method == http.MethodGet:
		writePage(w, r, f.hosts, func(h client.Host) any { return h })

	case version == "v2" && len(rest) == 0 && r.Method == http.MethodPost:
		var req client.HostCreateRequest
		if err := decode(r, &req); err != nil {
			writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
			return
		}
		if h, ok := f.createHost(w, req); ok {
			writeData(w, h)
		}

	case len(rest) >= 1:
		h, ok := f.hosts[rest[0]]
		if !ok {
			notFound(w)
			return
		}
		switch {
		case version == "v2" && len(rest) == 1 && r.Method == http.MethodGet:
			writeData(w, h)
		case version == "v3" && len(rest) == 1 && r.Method == http.MethodPut:
			f.hostPuts[h.ID]++
			var req client.HostUpdateRequest
			if err := decode(r, &req); err != nil {
				writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
				return
			}
			if !f.validHostShape(w, h, req.Name, req.RoleID, req.StaticAddresses, req.ListenPort, h.IsLighthouse, h.IsRelay) {
				return
			}
			applyHost(h, req.Name, req.RoleID, req.StaticAddresses, req.ListenPort, req.Tags, req.ConfigOverrides)
			writeData(w, h)
		case version == "v2" && len(rest) == 2 && rest[1] == "ip-addresses" && r.Method == http.MethodPost:
			var req client.HostAddIPRequest
			if err := decode(r, &req); err != nil {
				writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
				return
			}
			if slices.ContainsFunc(h.IPAddresses, func(a string) bool { return !strings.Contains(a, ":") }) {
				writeErr(w, 400, "ERR_HOST_ALREADY_HAS_IPV4", "host already has an IPv4 address", "")
				return
			}
			n := f.networks[h.NetworkID]
			if !slices.ContainsFunc(n.CIDRs, func(c string) bool { return !strings.Contains(c, ":") }) {
				writeErr(w, 400, "ERR_OUT_OF_RANGE", "network does not have an IPv4 prefix", "ipAddress")
				return
			}
			// The create path's checks cover range, prefix match and taken addresses; only its IPv4 result is used.
			ips, ok := f.assignHostIPs(w, n, []string{req.IPAddress})
			if !ok {
				return
			}
			if len(ips) == 0 || strings.Contains(ips[0], ":") {
				writeErr(w, 400, "ERR_INVALID_VALUE", "must be an IPv4 address or the network's IPv4 CIDR", "ipAddress")
				return
			}
			h.IPAddresses = append([]string{ips[0]}, h.IPAddresses...)
			writeData(w, h)
		case version == "v1" && len(rest) == 1 && r.Method == http.MethodDelete:
			delete(f.hosts, rest[0])
			writeData(w, map[string]any{})
		case version == "v1" && len(rest) == 2 && rest[1] == "enrollment-code" && r.Method == http.MethodPost:
			var req client.EnrollmentCodeRequest
			if err := decode(r, &req); err != nil {
				writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
				return
			}
			if code, ok := f.mintEnrollmentCode(w, h, req.LifetimeSeconds); ok {
				writeData(w, code)
			}
		default:
			notFound(w)
		}
	default:
		notFound(w)
	}
}

func (f *fakeAPI) createHost(w http.ResponseWriter, req client.HostCreateRequest) (*client.Host, bool) {
	n, ok := f.networks[req.NetworkID]
	if !ok {
		writeErr(w, 400, "ERR_INVALID_REFERENCE", "referenced value is invalid", "networkID")
		return nil, false
	}
	h := &client.Host{ID: newID("host"), NetworkID: n.ID, IsLighthouse: req.IsLighthouse, IsRelay: req.IsRelay}
	if !f.validHostShape(w, h, req.Name, req.RoleID, req.StaticAddresses, req.ListenPort, req.IsLighthouse, req.IsRelay) {
		return nil, false
	}
	ips, ok := f.assignHostIPs(w, n, req.IPAddresses)
	if !ok {
		return nil, false
	}
	h.IPAddresses = ips
	applyHost(h, req.Name, req.RoleID, req.StaticAddresses, req.ListenPort, req.Tags, req.ConfigOverrides)
	f.hosts[h.ID] = h
	return h, true
}

// mintEnrollmentCode mirrors postHostEnrollmentCode: blocked hosts are
// refused, the lifetime defaults to a day and is bounded like the API's.
func (f *fakeAPI) mintEnrollmentCode(w http.ResponseWriter, h *client.Host, lifetime *int64) (client.EnrollmentCode, bool) {
	if h.IsBlocked {
		writeErr(w, 400, "ERR_HOST_BLOCKED", "cannot create enrollment code for blocked host - unblock the host to continue", "")
		return client.EnrollmentCode{}, false
	}
	code := client.EnrollmentCode{Code: newID("")[1:], LifetimeSeconds: 86400}
	if lifetime != nil {
		code.LifetimeSeconds = *lifetime
	}
	if code.LifetimeSeconds < 60 || code.LifetimeSeconds > 604800 {
		writeErr(w, 400, "ERR_INVALID_VALUE", "must be between 60 and 604800", "lifetimeSeconds")
		return client.EnrollmentCode{}, false
	}
	f.enrollmentCodes[h.ID] = append(f.enrollmentCodes[h.ID], code)
	return code, true
}
