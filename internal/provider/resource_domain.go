package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

var (
	_ resource.Resource                = (*domainResource)(nil)
	_ resource.ResourceWithConfigure   = (*domainResource)(nil)
	_ resource.ResourceWithImportState = (*domainResource)(nil)
)

func newDomainResource() resource.Resource { return &domainResource{} }

type domainResource struct {
	client *client.Client
}

type domainModel struct {
	ID                      types.String `tfsdk:"id"`
	DomainName              types.String `tfsdk:"domain_name"`
	Verified                types.Bool   `tfsdk:"verified"`
	VerificationRecordName  types.String `tfsdk:"verification_record_name"`
	VerificationRecordValue types.String `tfsdk:"verification_record_value"`
}

func (r *domainResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_domain"
}

func (r *domainResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Registers a domain for endpoint SSO. Creating the domain only reserves it; ownership is proven " +
			"by publishing the TXT record in `verification_record_name` and `verification_record_value`, then verifying it " +
			"with `definednet_domain_verification`. An enabled endpoint OIDC provider requires a verified domain.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Domain ID, e.g. `domain-NFDI5G3RPXLHCPEXBVKEVLWPNI`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"domain_name": schema.StringAttribute{
				MarkdownDescription: "Domain name, e.g. `example.com`, in lowercase. The API does not rename domains, so changing this replaces the resource.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.UTF8LengthBetween(3, 255),
					domainNameValidator{},
				},
			},
			"verified": schema.BoolAttribute{
				MarkdownDescription: "Whether ownership has been verified.",
				Computed:            true,
			},
			"verification_record_name": schema.StringAttribute{
				MarkdownDescription: "Fully qualified name of the TXT record to publish, e.g. `_defined_h50gs8u9.example.com`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"verification_record_value": schema.StringAttribute{
				MarkdownDescription: "Value the TXT record must hold.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *domainResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *domainResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan domainModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domain, err := r.client.CreateDomain(ctx, client.DomainCreateRequest{DomainName: plan.DomainName.ValueString()})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create domain", fmt.Sprintf("domain %q: %s", plan.DomainName.ValueString(), describeError(err)))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, flattenDomain(domain))...)
}

func (r *domainResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state domainModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	domain, err := r.client.GetDomain(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read domain", fmt.Sprintf("domain %q: %s", state.ID.ValueString(), err))
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, flattenDomain(domain))...)
}

// Update is never called: the only configurable attribute requires replacement.
func (r *domainResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Unable to update domain", "Domains cannot be updated in place. This is a bug in the provider.")
}

func (r *domainResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state domainModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	err := r.client.DeleteDomain(ctx, state.ID.ValueString())
	if err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("Unable to delete domain", fmt.Sprintf("domain %q: %s", state.ID.ValueString(), describeError(err)))
	}
}

func (r *domainResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func flattenDomain(d *client.Domain) domainModel {
	return domainModel{
		ID:                      types.StringValue(d.ID),
		DomainName:              types.StringValue(d.DomainName),
		Verified:                types.BoolValue(d.IsVerified),
		VerificationRecordName:  types.StringValue(d.Zone + "." + d.DomainName),
		VerificationRecordValue: types.StringValue(d.Value),
	}
}
