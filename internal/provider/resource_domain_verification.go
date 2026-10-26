package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

var (
	_ resource.Resource                = (*domainVerificationResource)(nil)
	_ resource.ResourceWithConfigure   = (*domainVerificationResource)(nil)
	_ resource.ResourceWithImportState = (*domainVerificationResource)(nil)
)

const defaultVerifyTimeout = 10 * time.Minute

// verifyPollInterval is the wait between verification attempts while the TXT
// record propagates. It is a variable so tests can shorten it.
var verifyPollInterval = 10 * time.Second

// Verification codes the API returns while a correct record has not reached
// its resolver yet. Anything else is a real failure.
var retryableVerifyCodes = []string{
	"ERR_DOMAIN_VERIFICATION_FAILED_NXDOMAIN",
	"ERR_DOMAIN_VERIFICATION_FAILED_NO_RECORDS",
	"ERR_DOMAIN_VERIFICATION_FAILURE_INCORRECT",
}

func newDomainVerificationResource() resource.Resource { return &domainVerificationResource{} }

type domainVerificationResource struct {
	client *client.Client
}

type domainVerificationModel struct {
	ID       types.String   `tfsdk:"id"`
	DomainID types.String   `tfsdk:"domain_id"`
	Timeouts timeouts.Value `tfsdk:"timeouts"`
}

func (r *domainVerificationResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_domain_verification"
}

func (r *domainVerificationResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Verifies ownership of a `definednet_domain`. Create asks the API to look up the domain's TXT record " +
			"and keeps retrying until it is found or the create timeout passes, so the record can be published by a " +
			"DNS resource in the same configuration (use `depends_on`). Reference `domain_id` from this resource, not " +
			"from the domain, in resources that need a verified domain so they are ordered after verification. " +
			"The API has no un-verify, so destroying this resource only forgets it.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Same as `domain_id`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{idFromDomainID{}},
			},
			"domain_id": schema.StringAttribute{
				MarkdownDescription: "ID of the `definednet_domain` to verify.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
		},
		Blocks: map[string]schema.Block{
			"timeouts": timeouts.Block(ctx, timeouts.Opts{
				Create:            true,
				CreateDescription: "How long to keep retrying verification while the TXT record propagates. Defaults to `10m`.",
			}),
		},
	}
}

func (r *domainVerificationResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *domainVerificationResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan domainVerificationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	timeout, diags := plan.Timeouts.Create(ctx, defaultVerifyTimeout)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	id := plan.DomainID.ValueString()
	if err := r.verify(ctx, id); err != nil {
		resp.Diagnostics.AddError("Unable to verify domain", fmt.Sprintf("domain %q: %s", id, err))
		return
	}

	plan.ID = types.StringValue(id)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// verify polls the verify endpoint until the record is found, the error is
// not a propagation error, or ctx ends. A domain verified out of band (for
// example in the admin UI) needs no request.
func (r *domainVerificationResource) verify(ctx context.Context, id string) error {
	domain, err := r.client.GetDomain(ctx, id)
	if err != nil {
		return err
	}
	if domain.IsVerified {
		return nil
	}

	timedOut := func(last error) error {
		return fmt.Errorf("timed out waiting for TXT record %s.%s to resolve; last result: %w", domain.Zone, domain.DomainName, last)
	}
	var lastErr error
	for {
		err := r.client.VerifyDomain(ctx, id)
		if err == nil {
			return nil
		}
		// The deadline can land mid-request; report the last real lookup result, not the cancelled call.
		if ctx.Err() != nil {
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return ctx.Err() // interrupted by Terraform, not timed out
			}
			if lastErr == nil {
				lastErr = err
			}
			return timedOut(lastErr)
		}
		// Verify is idempotent, so unlike creates it is safe to retry through
		// the 5xx the API returns for resolver failures, a lingering 429, and
		// dropped connections. Only a 4xx that is not a propagation code is final.
		var apiErr *client.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode < http.StatusInternalServerError &&
			apiErr.StatusCode != http.StatusTooManyRequests && !hasAnyCode(apiErr, retryableVerifyCodes) {
			return err
		}
		lastErr = err

		select {
		case <-ctx.Done():
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return ctx.Err()
			}
			return timedOut(lastErr)
		case <-time.After(verifyPollInterval):
		}
	}
}

func (r *domainVerificationResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state domainVerificationModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	id := state.ID.ValueString()
	domain, err := r.client.GetDomain(ctx, id)
	// A deleted or unverified domain both mean the verification no longer
	// holds; dropping it from state makes the next apply verify again.
	if client.IsNotFound(err) || (err == nil && !domain.IsVerified) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read domain", fmt.Sprintf("domain %q: %s", id, err))
		return
	}

	state.DomainID = types.StringValue(id)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update only runs for a timeouts change (domain_id requires replacement);
// nothing is stored remotely, so the plan becomes the state.
func (r *domainVerificationResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan domainVerificationModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// Delete only forgets the verification: the API cannot un-verify a domain.
func (r *domainVerificationResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
}

func (r *domainVerificationResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func hasAnyCode(e *client.APIError, codes []string) bool {
	for _, c := range codes {
		if e.HasCode(c) {
			return true
		}
	}
	return false
}

// idFromDomainID plans id as domain_id whenever that is known. Without it a
// verification created while its domain already exists plans id as unknown,
// and a downstream RequiresReplace attribute referencing it would be replaced.
type idFromDomainID struct{}

func (idFromDomainID) Description(context.Context) string { return "id equals domain_id" }

func (m idFromDomainID) MarkdownDescription(ctx context.Context) string { return m.Description(ctx) }

func (idFromDomainID) PlanModifyString(ctx context.Context, req planmodifier.StringRequest, resp *planmodifier.StringResponse) {
	var domainID types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("domain_id"), &domainID)...)
	if !domainID.IsNull() && !domainID.IsUnknown() {
		resp.PlanValue = domainID
	}
}
