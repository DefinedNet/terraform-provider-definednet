package provider

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
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

	// tagUpdates holds the last PUT body received for each tag.
	tagUpdates map[string]client.TagUpdateRequest
	// networkOverrides and networkOverridePuts hold each network's config
	// overrides and how many times they were PUT.
	networkOverrides    map[string][]client.ConfigOverride
	networkOverridePuts map[string]int
	// rolePuts counts PUTs per role.
	rolePuts map[string]int

	server *httptest.Server
}

func newFakeAPI() *fakeAPI {
	f := &fakeAPI{
		apiKey:              "test-key",
		roles:               map[string]*client.Role{},
		tags:                map[string]*client.Tag{},
		routes:              map[string]*client.Route{},
		networks:            map[string]*client.Network{},
		tagUpdates:          map[string]client.TagUpdateRequest{},
		networkOverrides:    map[string][]client.ConfigOverride{},
		networkOverridePuts: map[string]int{},
		rolePuts:            map[string]int{},
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
		case http.MethodPut:
			var req client.TagUpdateRequest
			if err := decode(r, &req); err != nil {
				writeErr(w, 400, "ERR_BAD_REQUEST", err.Error(), "")
				return
			}
			f.tagUpdates[tag.Name] = req
			rules := req.FirewallRules
			if rules == nil {
				// The real API leaves rules untouched on a null firewallRules.
				rules = tag.FirewallRules
			}
			f.applyTag(tag, req.Description, req.ConfigOverrides, req.RouteSubscriptions, rules)
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
