package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
)

// stateSetter is satisfied by *tfsdk.State so resources can share one
// state-writing helper across Create, Read, and Update.
type stateSetter interface {
	Set(ctx context.Context, val any) diag.Diagnostics
}
