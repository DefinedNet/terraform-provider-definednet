package provider

import (
	"errors"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
)

// describeError renders an API error for a diagnostic, adding the next step
// for the two codes whose fix is not obvious from the API message.
func describeError(err error) string {
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) {
		return err.Error()
	}
	switch {
	case apiErr.HasCode("ERR_HAS_DEPENDENTS"):
		return err.Error() + ". Hosts still reference it; remove it from them first."
	case apiErr.HasCode("ERR_DUPLICATE_VALUE"):
		return err.Error() + ". An object with this name already exists; bring it under management with terraform import."
	}
	return err.Error()
}
