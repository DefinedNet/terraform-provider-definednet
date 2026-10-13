package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-jsontypes/jsontypes"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
)

var (
	_ resource.Resource                = (*tagResource)(nil)
	_ resource.ResourceWithConfigure   = (*tagResource)(nil)
	_ resource.ResourceWithImportState = (*tagResource)(nil)
)

func newTagResource() resource.Resource { return &tagResource{} }

type tagResource struct {
	client *client.Client
}

type tagModel struct {
	ID                 types.String `tfsdk:"id"`
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	Before             types.String `tfsdk:"before"`
	After              types.String `tfsdk:"after"`
	Priority           types.Int64  `tfsdk:"priority"`
	ConfigOverrides    types.Set    `tfsdk:"config_overrides"`
	RouteSubscriptions types.Set    `tfsdk:"route_subscriptions"`
	FirewallRules      types.Set    `tfsdk:"firewall_rules"`
}

type configOverrideModel struct {
	Key   types.String         `tfsdk:"key"`
	Value jsontypes.Normalized `tfsdk:"value"`
}

var configOverrideObjectType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"key":   types.StringType,
	"value": jsontypes.NormalizedType{},
}}

func (r *tagResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_tag"
}

func (r *tagResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a tag. Tags are `key:value` labels applied to hosts; a tag can carry nebula config overrides, " +
			"route subscriptions, and additional inbound firewall rules.\n\n" +
			"Tags are addressed by name, so changing `name` replaces the resource. Tag priority is managed by the API: " +
			"use `before` or `after` to position a tag relative to another one.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Same as `name`; tags have no separate ID.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Tag in `key:value` form. Key is at most 20 characters, value at most 50, no surrounding whitespace. Changing it forces a new tag.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(tagNameRegexp, "must be a key:value tag with no surrounding whitespace")},
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Optional description, at most 255 characters.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
				Validators:          []validator.String{stringvalidator.LengthAtMost(255)},
			},
			"before": schema.StringAttribute{
				MarkdownDescription: "Position this tag before the named tag (lower precedence than it). Sent on create and whenever `before` or `after` changes; " +
					"the API does not report it back, so it is not detected as drift. Conflicts with `after`.",
				Optional: true,
				Validators: []validator.String{
					stringvalidator.ConflictsWith(path.MatchRoot("after")),
					stringvalidator.RegexMatches(tagNameRegexp, "must be a key:value tag with no surrounding whitespace"),
				},
			},
			"after": schema.StringAttribute{
				MarkdownDescription: "Position this tag after the named tag (higher precedence than it). Sent on create and whenever `before` or `after` changes; " +
					"the API does not report it back, so it is not detected as drift. Conflicts with `before`.",
				Optional: true,
				Validators: []validator.String{
					stringvalidator.RegexMatches(tagNameRegexp, "must be a key:value tag with no surrounding whitespace"),
				},
			},
			"priority": schema.Int64Attribute{
				MarkdownDescription: "Precedence assigned by the API. Overrides from a higher priority win over lower ones.",
				Computed:            true,
				// No UseStateForUnknown: placing any other tag in the same
				// apply can shift this one, and a planned known value would
				// then fail as an inconsistent result.
			},
			"config_overrides": schema.SetNestedAttribute{
				MarkdownDescription: "Nebula config overrides applied to hosts with this tag. `value` is JSON, so use `jsonencode()`: " +
					"`jsonencode(\"info\")` for a string key, `jsonencode(4242)` for a number, `jsonencode([\"10.0.0.1\"])` for a list.",
				Optional: true,
				Computed: true,
				Default:  setdefault.StaticValue(types.SetValueMust(configOverrideObjectType, []attr.Value{})),
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"key": schema.StringAttribute{
							MarkdownDescription: "Dotted nebula config key, e.g. `lighthouse.dns.host`.",
							Required:            true,
						},
						"value": schema.StringAttribute{
							MarkdownDescription: "JSON-encoded value for the key.",
							Required:            true,
							CustomType:          jsontypes.NormalizedType{},
						},
					},
				},
			},
			"route_subscriptions": schema.SetAttribute{
				MarkdownDescription: "Route IDs every host with this tag is subscribed to. At most 100.",
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				Default:             setdefault.StaticValue(types.SetValueMust(types.StringType, []attr.Value{})),
				Validators:          []validator.Set{setvalidator.SizeAtMost(100)},
			},
			"firewall_rules": firewallRulesSchema(false, "Inbound firewall rules applied to hosts with this tag, in addition to their role's rules. At most 50."),
		},
	}
}

func (r *tagResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *tagResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan tagModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := client.TagCreateRequest{
		Name:        plan.Name.ValueString(),
		Description: plan.Description.ValueString(),
		Before:      optionalString(plan.Before),
		After:       optionalString(plan.After),
	}
	var diags diag.Diagnostics
	body.ConfigOverrides, diags = expandConfigOverrides(ctx, plan.ConfigOverrides)
	resp.Diagnostics.Append(diags...)
	body.RouteSubscriptions, diags = expandStringSet(ctx, plan.RouteSubscriptions)
	resp.Diagnostics.Append(diags...)
	body.FirewallRules, diags = expandFirewallRules(ctx, plan.FirewallRules, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tag, err := r.client.CreateTag(ctx, body)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create tag", fmt.Sprintf("tag %q: %s", plan.Name.ValueString(), err))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, tag, plan, &resp.State)...)
}

func (r *tagResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state tagModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	tag, err := r.client.GetTag(ctx, state.Name.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read tag", fmt.Sprintf("tag %q: %s", state.Name.ValueString(), err))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, tag, state, &resp.State)...)
}

func (r *tagResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state tagModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	body := client.TagUpdateRequest{
		Description: plan.Description.ValueString(),
	}
	// Re-sending an unchanged before can still shuffle priorities, which
	// pushes new config to every host carrying the tag's overrides.
	if !plan.Before.Equal(state.Before) || !plan.After.Equal(state.After) {
		body.Before = optionalString(plan.Before)
		body.After = optionalString(plan.After)
	}
	var diags diag.Diagnostics
	body.ConfigOverrides, diags = expandConfigOverrides(ctx, plan.ConfigOverrides)
	resp.Diagnostics.Append(diags...)
	body.RouteSubscriptions, diags = expandStringSet(ctx, plan.RouteSubscriptions)
	resp.Diagnostics.Append(diags...)
	body.FirewallRules, diags = expandFirewallRules(ctx, plan.FirewallRules, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	tag, err := r.client.UpdateTag(ctx, plan.Name.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("Unable to update tag", fmt.Sprintf("tag %q: %s", plan.Name.ValueString(), err))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, tag, plan, &resp.State)...)
}

func (r *tagResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tagModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteTag(ctx, state.Name.ValueString())
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete tag", fmt.Sprintf("tag %q: %s", state.Name.ValueString(), err))
	}
}

func (r *tagResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
}

// setState writes the API tag into state. before/after are positioning
// commands the API never echoes back, so they are carried over from ref.
func (r *tagResource) setState(ctx context.Context, tag *client.Tag, ref tagModel, state stateSetter) diag.Diagnostics {
	var diags diag.Diagnostics

	rules, d := flattenFirewallRules(ctx, tag.FirewallRules, false)
	diags.Append(d...)
	overrides, d := flattenConfigOverrides(ctx, tag.ConfigOverrides, ref.ConfigOverrides)
	diags.Append(d...)
	subs, d := types.SetValueFrom(ctx, types.StringType, nonNilStrings(tag.RouteSubscriptions))
	diags.Append(d...)
	if diags.HasError() {
		return diags
	}

	m := tagModel{
		ID:                 types.StringValue(tag.Name),
		Name:               types.StringValue(tag.Name),
		Description:        types.StringValue(tag.Description),
		Before:             ref.Before,
		After:              ref.After,
		Priority:           types.Int64Value(tag.Priority),
		ConfigOverrides:    overrides,
		RouteSubscriptions: subs,
		FirewallRules:      rules,
	}
	diags.Append(state.Set(ctx, &m)...)
	return diags
}

func expandConfigOverrides(ctx context.Context, set types.Set) ([]client.ConfigOverride, diag.Diagnostics) {
	var diags diag.Diagnostics
	out := []client.ConfigOverride{}
	if set.IsNull() || set.IsUnknown() {
		return out, diags
	}
	var models []configOverrideModel
	diags.Append(set.ElementsAs(ctx, &models, false)...)
	if diags.HasError() {
		return nil, diags
	}
	for _, m := range models {
		raw := json.RawMessage(m.Value.ValueString())
		if !json.Valid(raw) {
			diags.AddError("Invalid config override value",
				"config_overrides value for key "+m.Key.ValueString()+" is not valid JSON; wrap it with jsonencode().")
			continue
		}
		out = append(out, client.ConfigOverride{Key: m.Key.ValueString(), Value: raw})
	}
	return out, diags
}

// flattenConfigOverrides converts API overrides into a Terraform set. When an
// override's value is semantically the same JSON as the one in ref (plan or
// prior state), ref's text is kept: the API re-serializes stored values, and
// preserving the configured text keeps set elements byte-identical.
func flattenConfigOverrides(ctx context.Context, overrides []client.ConfigOverride, ref types.Set) (types.Set, diag.Diagnostics) {
	var diags diag.Diagnostics

	refOverrides, d := expandConfigOverrides(ctx, ref)
	diags.Append(d...)
	if diags.HasError() {
		return types.SetNull(configOverrideObjectType), diags
	}

	elems := make([]attr.Value, 0, len(overrides))
	for _, o := range overrides {
		value := jsontypes.NewNormalizedValue(string(o.Value))
		for _, want := range refOverrides {
			if want.Key != o.Key {
				continue
			}
			refValue := jsontypes.NewNormalizedValue(string(want.Value))
			if eq, d := value.StringSemanticEquals(ctx, refValue); eq && !d.HasError() {
				value = refValue
			}
			break
		}
		obj, d := types.ObjectValue(configOverrideObjectType.AttrTypes, map[string]attr.Value{
			"key":   types.StringValue(o.Key),
			"value": value,
		})
		diags.Append(d...)
		elems = append(elems, obj)
	}
	set, d := types.SetValue(configOverrideObjectType, elems)
	diags.Append(d...)
	return set, diags
}

func expandStringSet(ctx context.Context, set types.Set) ([]string, diag.Diagnostics) {
	out := []string{}
	if set.IsNull() || set.IsUnknown() {
		return out, nil
	}
	diags := set.ElementsAs(ctx, &out, false)
	return out, diags
}

func optionalString(s types.String) *string {
	if s.IsNull() || s.IsUnknown() {
		return nil
	}
	return s.ValueStringPointer()
}

// nonNilStrings turns a nil slice into an empty one so a null API array and
// an empty one both land in state as an empty set.
func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
