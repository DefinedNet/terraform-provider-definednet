package provider

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// networkPrivateSpaces mirrors the API's private-network check, which also
// admits the CGNAT range that netip.Addr.IsPrivate does not.
var networkPrivateSpaces = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
}

// ipv4PrefixValidator rejects at plan time what the API would reject at apply
// time: anything other than an IPv4 prefix with no host bits set, plus the
// optional mask-length and private-space rules for network prefixes.
type ipv4PrefixValidator struct {
	allowAny         bool
	minBits, maxBits int
	private          bool
}

func (v ipv4PrefixValidator) Description(_ context.Context) string {
	d := "must be an IPv4 network in CIDR form with no host bits set, such as 10.0.0.0/24"
	if v.allowAny {
		d = "must be ANY or an IPv4 network in CIDR form with no host bits set, such as 10.0.0.0/24"
	}
	if v.maxBits > 0 {
		d += fmt.Sprintf(", with a prefix length from /%d to /%d", v.minBits, v.maxBits)
	}
	if v.private {
		d += ", inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or 100.64.0.0/10"
	}
	return d
}

func (v ipv4PrefixValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v ipv4PrefixValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	s := req.ConfigValue.ValueString()
	if v.allowAny && s == "ANY" {
		return
	}
	if !v.valid(s) {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid CIDR", fmt.Sprintf("%q %s.", s, v.Description(ctx)))
	}
}

func (v ipv4PrefixValidator) valid(s string) bool {
	p, err := netip.ParsePrefix(s)
	if err != nil || !p.Addr().Is4() || p != p.Masked() {
		return false
	}
	if v.maxBits > 0 && (p.Bits() < v.minBits || p.Bits() > v.maxBits) {
		return false
	}
	if v.private {
		for _, space := range networkPrivateSpaces {
			if prefixContains(space, p) {
				return true
			}
		}
		return false
	}
	return true
}

// prefixContains reports whether inner lies entirely within outer.
func prefixContains(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// portRangeValidator rejects a range whose from port is above its to port.
type portRangeValidator struct{}

func (portRangeValidator) Description(_ context.Context) string {
	return "from must be less than or equal to to"
}

func (v portRangeValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (portRangeValidator) ValidateObject(_ context.Context, req validator.ObjectRequest, resp *validator.ObjectResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	attrs := req.ConfigValue.Attributes()
	from, fromOK := knownInt64(attrs["from"])
	to, toOK := knownInt64(attrs["to"])
	if fromOK && toOK && from > to {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid port range",
			fmt.Sprintf("from (%d) must be less than or equal to to (%d).", from, to))
	}
}

func knownInt64(v attr.Value) (int64, bool) {
	i, ok := v.(types.Int64)
	if !ok || i.IsNull() || i.IsUnknown() {
		return 0, false
	}
	return i.ValueInt64(), true
}

// uniqueOverrideKeys rejects config_overrides that name the same key twice,
// which the API refuses at apply time.
type uniqueOverrideKeys struct{}

func (uniqueOverrideKeys) Description(_ context.Context) string {
	return "each config override key may appear only once"
}

func (v uniqueOverrideKeys) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (uniqueOverrideKeys) ValidateSet(_ context.Context, req validator.SetRequest, resp *validator.SetResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	seen := map[string]bool{}
	for _, elem := range req.ConfigValue.Elements() {
		obj, ok := elem.(types.Object)
		if !ok || obj.IsUnknown() {
			continue
		}
		key, ok := obj.Attributes()["key"].(types.String)
		if !ok || key.IsUnknown() || key.IsNull() {
			continue
		}
		if seen[key.ValueString()] {
			resp.Diagnostics.AddAttributeError(req.Path, "Duplicate config override key",
				fmt.Sprintf("The key %q is set more than once; the API rejects duplicate override keys.", key.ValueString()))
		}
		seen[key.ValueString()] = true
	}
}

// noSelfRoleValidator rejects the selfRoleID placeholder on tag and route
// rules, which have no own role to resolve it to.
type noSelfRoleValidator struct{}

func (noSelfRoleValidator) Description(_ context.Context) string {
	return "\"self\" is only valid in a definednet_role, where it means that role"
}

func (v noSelfRoleValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v noSelfRoleValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.ValueString() == selfRoleID {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid allowed_role_id",
			v.Description(ctx)+"; use a role's id here.")
	}
}

// domainNameValidator rejects what the API would reject (no leading or
// trailing dot, at least one dot) and anything strings.ToLower would change,
// because the API lowercases the name with it and an uppercase letter in
// configuration would otherwise never match the refreshed state.
type domainNameValidator struct{}

func (domainNameValidator) Description(_ context.Context) string {
	return "must be a lowercase domain name with at least one dot and no leading or trailing dot"
}

func (v domainNameValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (v domainNameValidator) ValidateString(ctx context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	s := req.ConfigValue.ValueString()
	ok := s == strings.ToLower(s) && s == strings.TrimSpace(s) &&
		!strings.HasPrefix(s, ".") && !strings.HasSuffix(s, ".") && strings.Contains(s, ".")
	if !ok {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid domain name", v.Description(ctx))
	}
}
