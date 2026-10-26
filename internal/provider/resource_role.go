package provider

import (
	"context"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
)

var (
	_ resource.Resource                = (*roleResource)(nil)
	_ resource.ResourceWithConfigure   = (*roleResource)(nil)
	_ resource.ResourceWithImportState = (*roleResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*roleResource)(nil)
)

func newRoleResource() resource.Resource { return &roleResource{} }

type roleResource struct {
	client *client.Client
}

type roleModel struct {
	ID            types.String `tfsdk:"id"`
	Name          types.String `tfsdk:"name"`
	Description   types.String `tfsdk:"description"`
	FirewallRules types.Set    `tfsdk:"firewall_rules"`
}

func (r *roleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func (r *roleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages a role. Roles carry the inbound firewall rules applied to every host assigned to them.\n\n" +
			"The API does not support renaming a role, so changing `name` replaces the resource. " +
			"Deleting a role that still has hosts assigned fails with `ERR_HAS_DEPENDENTS`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Role ID, e.g. `role-LO4SPDSWTZNJC676WFCZKUB3ZQ`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Role name, 1-50 characters. Changing it forces a new role.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.UTF8LengthBetween(1, 50)},
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"description": schema.StringAttribute{
				MarkdownDescription: "Optional description, at most 255 characters.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString(""),
				Validators:          []validator.String{stringvalidator.UTF8LengthAtMost(255)},
			},
			"firewall_rules": firewallRulesSchema(false, true, "Inbound firewall rules applied to hosts with this role. "+
				"`allowed_role_id = \"self\"` allows hosts with this same role."),
		},
	}
}

func (r *roleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *roleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rules, diags := expandFirewallRules(ctx, plan.FirewallRules, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	// The API rejects unknown role IDs, so rules allowing the role itself
	// cannot be sent until its ID exists.
	initial := []client.FirewallRule{}
	for _, rule := range rules {
		if !isSelfRule(rule) {
			initial = append(initial, rule)
		}
	}

	role, err := r.client.CreateRole(ctx, client.RoleCreateRequest{
		Name:          plan.Name.ValueString(),
		Description:   plan.Description.ValueString(),
		FirewallRules: initial,
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create role", fmt.Sprintf("role %q: %s", plan.Name.ValueString(), describeError(err)))
		return
	}

	if len(initial) != len(rules) {
		// State is written before the PUT so a failure there leaves the role
		// tainted instead of orphaned.
		resp.Diagnostics.Append(r.setState(ctx, role, &resp.State)...)
		role, err = r.client.UpdateRole(ctx, role.ID, client.RoleUpdateRequest{
			Description:   plan.Description.ValueString(),
			FirewallRules: resolveSelf(rules, role.ID),
		})
		if err != nil {
			resp.Diagnostics.AddError("Unable to set role firewall rules", fmt.Sprintf("role %q: %s", plan.Name.ValueString(), describeError(err)))
			return
		}
	}

	resp.Diagnostics.Append(r.setState(ctx, role, &resp.State)...)
}

func (r *roleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	role, err := r.client.GetRole(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read role", fmt.Sprintf("role %q: %s", state.ID.ValueString(), err))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, role, &resp.State)...)
}

func (r *roleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rules, diags := expandFirewallRules(ctx, plan.FirewallRules, false)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	role, err := r.client.UpdateRole(ctx, plan.ID.ValueString(), client.RoleUpdateRequest{
		Description:   plan.Description.ValueString(),
		FirewallRules: resolveSelf(rules, plan.ID.ValueString()),
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to update role", fmt.Sprintf("role %q: %s", plan.ID.ValueString(), err))
		return
	}

	resp.Diagnostics.Append(r.setState(ctx, role, &resp.State)...)
}

func (r *roleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteRole(ctx, state.ID.ValueString())
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete role", fmt.Sprintf("role %q: %s", state.ID.ValueString(), describeError(err)))
	}
}

func (r *roleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// ModifyPlan rejects a rule naming the role's own ID literally. Read always
// reports that rule as selfRoleID, so a literal spelling would plan a change
// on every run. The ID is unknown on create, so only updates can hit this.
func (r *roleResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var plan roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() || plan.ID.IsUnknown() {
		return
	}
	for _, elem := range plan.FirewallRules.Elements() {
		// An unknown rule object has no attributes yet.
		if v, ok := elem.(types.Object).Attributes()["allowed_role_id"]; ok && v.Equal(plan.ID) {
			resp.Diagnostics.AddAttributeError(path.Root("firewall_rules"), "Invalid allowed_role_id",
				fmt.Sprintf("%q is this role's own ID; write %q instead.", plan.ID.ValueString(), selfRoleID))
			return
		}
	}
}

func (r *roleResource) setState(ctx context.Context, role *client.Role, state stateSetter) diag.Diagnostics {
	m, diags := flattenRole(ctx, role)
	if diags.HasError() {
		return diags
	}
	m.FirewallRules = markSelfRules(ctx, m.FirewallRules, role.ID)
	diags.Append(state.Set(ctx, &m)...)
	return diags
}

func isSelfRule(rule client.FirewallRule) bool {
	return rule.AllowedRoleID != nil && *rule.AllowedRoleID == selfRoleID
}

// resolveSelf returns rules with the selfRoleID placeholder replaced by id,
// which is the only form the API accepts.
func resolveSelf(rules []client.FirewallRule, id string) []client.FirewallRule {
	out := make([]client.FirewallRule, len(rules))
	for i, rule := range rules {
		if isSelfRule(rule) {
			rule.AllowedRoleID = &id
		}
		out[i] = rule
	}
	return out
}

// markSelfRules reports rules allowing the role's own id as selfRoleID, the
// only spelling the schema accepts for it.
func markSelfRules(ctx context.Context, rules types.Set, id string) types.Set {
	own := types.StringValue(id)
	elems := rules.Elements()
	for i, elem := range elems {
		obj := elem.(types.Object)
		attrs := obj.Attributes()
		if !attrs["allowed_role_id"].Equal(own) {
			continue
		}
		attrs["allowed_role_id"] = types.StringValue(selfRoleID)
		elems[i] = types.ObjectValueMust(obj.AttributeTypes(ctx), attrs)
	}
	return types.SetValueMust(rules.ElementType(ctx), elems)
}

func flattenRole(ctx context.Context, role *client.Role) (roleModel, diag.Diagnostics) {
	rules, diags := flattenFirewallRules(ctx, role.FirewallRules, false)
	return roleModel{
		ID:            types.StringValue(role.ID),
		Name:          types.StringValue(role.Name),
		Description:   types.StringValue(role.Description),
		FirewallRules: rules,
	}, diags
}
