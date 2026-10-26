package provider

import (
	"errors"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

// describeError renders an API error for a diagnostic, adding the next step
// for the codes whose fix is not obvious from the API message.
func describeError(err error) string {
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) {
		return err.Error()
	}
	switch {
	case apiErr.HasCode("ERR_DUPLICATE_VALUE"):
		return err.Error() + ". An object with this name already exists; bring it under management with terraform import."
	case apiErr.HasCode("ERR_DOMAIN_NOT_VERIFIED"):
		return err.Error() + ". Verify the domain first with definednet_domain_verification and reference its domain_id."
	case apiErr.HasCode("ERR_DOMAIN_ALREADY_ENABLED"):
		return err.Error() + ". Another enabled endpoint OIDC provider already holds this domain; disable it first."
	}
	return err.Error()
}
