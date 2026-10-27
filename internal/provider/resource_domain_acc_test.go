package provider

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
)

// Unverified domains need no DNS, so these use throwaway names. Only
// verification needs accDomain and its TXT record.

func TestAccDomainResource(t *testing.T) {
	name, renamed := accName()+".example.com", accName()+".example.com"
	runAccTest(t, []testStep{
		{
			config: fmt.Sprintf(`
resource "definednet_domain" "d" {
  domain_name = %q
}`, name),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrSet("definednet_domain.d", "id"),
				resource.TestCheckResourceAttr("definednet_domain.d", "verified", "false"),
				resource.TestMatchResourceAttr("definednet_domain.d", "verification_record_name", regexp.MustCompile(`^_defined_[a-z0-9]{8}\.`+regexp.QuoteMeta(name)+`$`)),
				resource.TestCheckResourceAttrSet("definednet_domain.d", "verification_record_value"),
			},
		},
		{importState: true, importResource: "definednet_domain.d"},
		{
			config: fmt.Sprintf(`
resource "definednet_domain" "d" {
  domain_name = %q
}`, renamed),
			planChecks: expectReplace("definednet_domain.d"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_domain.d", "domain_name", renamed),
			},
		},
	})
}

func TestAccDomainResource_RemovedOutOfBand(t *testing.T) {
	runAccRemovedOutOfBandTest(t, fmt.Sprintf(`
resource "definednet_domain" "d" {
  domain_name = "%s.example.com"
}`, accName()), "definednet_domain.d", func(c *client.Client, id string) error {
		return c.DeleteDomain(context.Background(), id)
	})
}

func TestAccDomainVerificationResource(t *testing.T) {
	cfg := fmt.Sprintf(`
resource "definednet_domain" "d" {
  domain_name = %q
}

resource "definednet_domain_verification" "d" {
  domain_id = definednet_domain.d.id
}
`, accDomain())
	runAccTest(t, []testStep{
		{
			config: cfg,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrPair("definednet_domain_verification.d", "id", "definednet_domain.d", "id"),
			},
		},
		{importState: true, importResource: "definednet_domain_verification.d"},
		{
			// The domain refreshes to verified on the next plan with no diff.
			config: cfg,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_domain.d", "verified", "true"),
			},
		},
	})
}
