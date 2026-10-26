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
			"firewall_rules": firewallRulesSchema(false, "Inbound firewall rules applied to hosts with this role."),
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

	role, err := r.client.CreateRole(ctx, client.RoleCreateRequest{
		Name:          plan.Name.ValueString(),
		Description:   plan.Description.ValueString(),
		FirewallRules: rules,
	})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create role", fmt.Sprintf("role %q: %s", plan.Name.ValueString(), describeError(err)))
		return
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
		FirewallRules: rules,
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

func (r *roleResource) setState(ctx context.Context, role *client.Role, state stateSetter) diag.Diagnostics {
	m, diags := flattenRole(ctx, role)
	if diags.HasError() {
		return diags
	}
	diags.Append(state.Set(ctx, &m)...)
	return diags
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
