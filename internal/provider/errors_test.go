package provider

import (
	"errors"
	"strings"
	"testing"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
)

func TestDescribeError(t *testing.T) {
	dep := &client.APIError{StatusCode: 400, Errors: []client.ErrorDetail{{Code: "ERR_HAS_DEPENDENTS", Message: "has dependents"}}}
	if got := describeError(dep); !strings.Contains(got, "Hosts still reference it") {
		t.Errorf("dependents hint missing: %q", got)
	}
	dup := &client.APIError{StatusCode: 400, Errors: []client.ErrorDetail{{Code: "ERR_DUPLICATE_VALUE", Path: "name"}}}
	if got := describeError(dup); !strings.Contains(got, "terraform import") {
		t.Errorf("duplicate hint missing: %q", got)
	}
	plain := errors.New("dial tcp: connection refused")
	if got := describeError(plain); got != plain.Error() {
		t.Errorf("plain error altered: %q", got)
	}
}
