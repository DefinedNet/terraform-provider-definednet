package provider

import (
	"context"
	"fmt"
	"net/netip"

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
