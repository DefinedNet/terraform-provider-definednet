package provider

import (
	"context"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	dsschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
)

// tagNameRegexp matches key:value with exactly one colon and no surrounding
// whitespace on either side, mirroring the API's HostTag validation.
var tagNameRegexp = regexp.MustCompile(`^[^\s:](?:[^:]{0,18}[^\s:])?:[^\s:](?:[^:]{0,48}[^\s:])?$`)

var portRangeAttrTypes = map[string]attr.Type{
	"from": types.Int64Type,
	"to":   types.Int64Type,
}

// firewallRuleAttrTypes returns the object type of a firewall rule element.
// Route rules carry a local_cidr; role and tag rules do not.
func firewallRuleAttrTypes(withLocalCIDR bool) map[string]attr.Type {
	m := map[string]attr.Type{
		"protocol":        types.StringType,
		"description":     types.StringType,
		"allowed_role_id": types.StringType,
		"allowed_tags":    types.SetType{ElemType: types.StringType},
		"port_range":      types.ObjectType{AttrTypes: portRangeAttrTypes},
	}
	if withLocalCIDR {
		m["local_cidr"] = types.StringType
	}
	return m
}

func firewallRuleObjectType(withLocalCIDR bool) types.ObjectType {
	return types.ObjectType{AttrTypes: firewallRuleAttrTypes(withLocalCIDR)}
}

// Field descriptions shared by the resource and data source schemas.
const (
	descRuleProtocol    = "Allowed protocol: `ANY`, `TCP`, `UDP`, or `ICMP`."
	descRuleDescription = "Optional description, at most 255 characters."
	descRuleRoleID      = "Only hosts with this role are allowed. Null allows every role."
	descRuleTags        = "Only hosts carrying every one of these `key:value` tags are allowed. Null allows any tags."
	descRulePortRange   = "Inclusive port range. Null allows every port."
	descRulePortFrom    = "First port in the range (1-65535)."
	descRulePortTo      = "Last port in the range (1-65535), at least `from`."
	descRuleLocalCIDR   = "IPv4 CIDR overlapping one of `routable_cidrs` that this rule applies to, or `ANY` for the whole route."
)

// firewallRulesSchema returns the shared firewall_rules attribute. It is a set
// because the API returns rules sorted by CIDR and port rather than in
// submission order. The set defaults to empty so that omitting it and writing
// [] plan identically, matching the API always returning an array.
func firewallRulesSchema(withLocalCIDR bool, description string) schema.SetNestedAttribute {
	attrs := map[string]schema.Attribute{
		"protocol": schema.StringAttribute{
			MarkdownDescription: descRuleProtocol,
			Required:            true,
			Validators:          []validator.String{stringvalidator.OneOf("ANY", "TCP", "UDP", "ICMP")},
		},
		"description": schema.StringAttribute{
			MarkdownDescription: descRuleDescription,
			Optional:            true,
			Computed:            true,
			Default:             stringdefault.StaticString(""),
			Validators:          []validator.String{stringvalidator.LengthAtMost(255)},
		},
		"allowed_role_id": schema.StringAttribute{
			MarkdownDescription: descRuleRoleID,
			Optional:            true,
		},
		"allowed_tags": schema.SetAttribute{
			MarkdownDescription: descRuleTags + " An empty set means the same thing to the API as null and is always reported back as null, " +
				"so it is rejected to keep the plan and refreshed state in agreement.",
			Optional:    true,
			ElementType: types.StringType,
			Validators: []validator.Set{
				setvalidator.SizeAtLeast(1),
				setvalidator.ValueStringsAre(stringvalidator.RegexMatches(tagNameRegexp, "must be a key:value tag with no surrounding whitespace")),
			},
		},
		"port_range": schema.SingleNestedAttribute{
			MarkdownDescription: descRulePortRange,
			Optional:            true,
			Validators:          []validator.Object{portRangeValidator{}},
			Attributes: map[string]schema.Attribute{
				"from": schema.Int64Attribute{
					MarkdownDescription: descRulePortFrom,
					Required:            true,
					Validators:          []validator.Int64{int64validator.Between(1, 65535)},
				},
				"to": schema.Int64Attribute{
					MarkdownDescription: descRulePortTo,
					Required:            true,
					Validators:          []validator.Int64{int64validator.Between(1, 65535)},
				},
			},
		},
	}
	if withLocalCIDR {
		attrs["local_cidr"] = schema.StringAttribute{
			MarkdownDescription: descRuleLocalCIDR,
			Required:            true,
			// The API accepts any casing of ANY but always reports it
			// uppercase, so only ANY is accepted to keep plans stable.
			Validators: []validator.String{ipv4PrefixValidator{allowAny: true}},
		}
	}

	return schema.SetNestedAttribute{
		MarkdownDescription: description,
		Optional:            true,
		Computed:            true,
		Default:             setdefault.StaticValue(types.SetValueMust(firewallRuleObjectType(withLocalCIDR), []attr.Value{})),
		NestedObject:        schema.NestedAttributeObject{Attributes: attrs},
	}
}

type portRangeModel struct {
	From types.Int64 `tfsdk:"from"`
	To   types.Int64 `tfsdk:"to"`
}

// firewallRuleModel is the Terraform shape of a role or tag rule.
type firewallRuleModel struct {
	Protocol      types.String    `tfsdk:"protocol"`
	Description   types.String    `tfsdk:"description"`
	AllowedRoleID types.String    `tfsdk:"allowed_role_id"`
	AllowedTags   types.Set       `tfsdk:"allowed_tags"`
	PortRange     *portRangeModel `tfsdk:"port_range"`
}

// routeFirewallRuleModel is the Terraform shape of a route rule.
type routeFirewallRuleModel struct {
	Protocol      types.String    `tfsdk:"protocol"`
	Description   types.String    `tfsdk:"description"`
	AllowedRoleID types.String    `tfsdk:"allowed_role_id"`
	AllowedTags   types.Set       `tfsdk:"allowed_tags"`
	PortRange     *portRangeModel `tfsdk:"port_range"`
	LocalCIDR     types.String    `tfsdk:"local_cidr"`
}

// expandFirewallRules converts a Terraform set into API rules. The result is
// never nil: every endpoint needs an explicit array to replace rules, and the
// tag PUT leaves rules untouched when the field is null.
func expandFirewallRules(ctx context.Context, set types.Set, withLocalCIDR bool) ([]client.FirewallRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	out := []client.FirewallRule{}
	if set.IsNull() || set.IsUnknown() {
		return out, diags
	}

	if withLocalCIDR {
		var models []routeFirewallRuleModel
		diags.Append(set.ElementsAs(ctx, &models, false)...)
		if diags.HasError() {
			return nil, diags
		}
		for _, m := range models {
			r, d := expandFirewallRule(ctx, m.Protocol, m.Description, m.AllowedRoleID, m.AllowedTags, m.PortRange)
			diags.Append(d...)
			r.LocalCIDR = m.LocalCIDR.ValueString()
			out = append(out, r)
		}
		return out, diags
	}

	var models []firewallRuleModel
	diags.Append(set.ElementsAs(ctx, &models, false)...)
	if diags.HasError() {
		return nil, diags
	}
	for _, m := range models {
		r, d := expandFirewallRule(ctx, m.Protocol, m.Description, m.AllowedRoleID, m.AllowedTags, m.PortRange)
		diags.Append(d...)
		out = append(out, r)
	}
	return out, diags
}

func expandFirewallRule(ctx context.Context, protocol, description, allowedRoleID types.String, allowedTags types.Set, portRange *portRangeModel) (client.FirewallRule, diag.Diagnostics) {
	var diags diag.Diagnostics
	r := client.FirewallRule{
		Protocol:    protocol.ValueString(),
		Description: description.ValueString(),
	}
	if !allowedRoleID.IsNull() && !allowedRoleID.IsUnknown() {
		r.AllowedRoleID = allowedRoleID.ValueStringPointer()
	}
	if !allowedTags.IsNull() && !allowedTags.IsUnknown() {
		diags.Append(allowedTags.ElementsAs(ctx, &r.AllowedTags, false)...)
	}
	if portRange != nil {
		r.PortRange = &client.PortRange{From: portRange.From.ValueInt64(), To: portRange.To.ValueInt64()}
	}
	return r, diags
}

// flattenFirewallRules converts API rules into a Terraform set. Empty
// allowedTags become null: the API treats null and [] identically and always
// reports null, and the schema rejects an empty set in config.
func flattenFirewallRules(ctx context.Context, rules []client.FirewallRule, withLocalCIDR bool) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics
	objType := firewallRuleObjectType(withLocalCIDR)

	elems := make([]attr.Value, 0, len(rules))
	for _, r := range rules {
		attrs := map[string]attr.Value{
			"protocol":        types.StringValue(r.Protocol),
			"description":     types.StringValue(r.Description),
			"allowed_role_id": types.StringPointerValue(r.AllowedRoleID),
		}

		if len(r.AllowedTags) == 0 {
			attrs["allowed_tags"] = types.SetNull(types.StringType)
		} else {
			set, d := types.SetValueFrom(ctx, types.StringType, r.AllowedTags)
			diags.Append(d...)
			attrs["allowed_tags"] = set
		}

		if r.PortRange == nil {
			attrs["port_range"] = types.ObjectNull(portRangeAttrTypes)
		} else {
			attrs["port_range"] = types.ObjectValueMust(portRangeAttrTypes, map[string]attr.Value{
				"from": types.Int64Value(r.PortRange.From),
				"to":   types.Int64Value(r.PortRange.To),
			})
		}

		if withLocalCIDR {
			attrs["local_cidr"] = types.StringValue(r.LocalCIDR)
		}

		obj, d := types.ObjectValue(objType.AttrTypes, attrs)
		diags.Append(d...)
		elems = append(elems, obj)
	}

	set, d := types.SetValue(objType, elems)
	diags.Append(d...)
	return set, diags
}

// firewallRulesDataSchema is the read-only data source counterpart of
// firewallRulesSchema with the same element type and field descriptions.
func firewallRulesDataSchema(withLocalCIDR bool, description string) dsschema.SetNestedAttribute {
	attrs := map[string]dsschema.Attribute{
		"protocol":        dsschema.StringAttribute{Computed: true, MarkdownDescription: descRuleProtocol},
		"description":     dsschema.StringAttribute{Computed: true, MarkdownDescription: descRuleDescription},
		"allowed_role_id": dsschema.StringAttribute{Computed: true, MarkdownDescription: descRuleRoleID},
		"allowed_tags":    dsschema.SetAttribute{Computed: true, ElementType: types.StringType, MarkdownDescription: descRuleTags},
		"port_range": dsschema.SingleNestedAttribute{
			Computed:            true,
			MarkdownDescription: descRulePortRange,
			Attributes: map[string]dsschema.Attribute{
				"from": dsschema.Int64Attribute{Computed: true, MarkdownDescription: descRulePortFrom},
				"to":   dsschema.Int64Attribute{Computed: true, MarkdownDescription: descRulePortTo},
			},
		},
	}
	if withLocalCIDR {
		attrs["local_cidr"] = dsschema.StringAttribute{Computed: true, MarkdownDescription: descRuleLocalCIDR}
	}
	return dsschema.SetNestedAttribute{
		MarkdownDescription: description,
		Computed:            true,
		NestedObject:        dsschema.NestedAttributeObject{Attributes: attrs},
	}
}
