package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
)

func TestDomainResource(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	runUnitTest(t, f, []testStep{
		{
			config: `
resource "definednet_domain" "d" {
  domain_name = "example.com"
}`,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrSet("definednet_domain.d", "id"),
				resource.TestCheckResourceAttr("definednet_domain.d", "domain_name", "example.com"),
				resource.TestCheckResourceAttr("definednet_domain.d", "verified", "false"),
				resource.TestMatchResourceAttr("definednet_domain.d", "verification_record_name", regexp.MustCompile(`^_defined_[a-z0-9]{8}\.example\.com$`)),
				resource.TestCheckResourceAttrSet("definednet_domain.d", "verification_record_value"),
			},
		},
		{importState: true, importResource: "definednet_domain.d"},
		{
			config: `
resource "definednet_domain" "d" {
  domain_name = "other.example.com"
}`,
			planChecks: expectReplace("definednet_domain.d"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_domain.d", "domain_name", "other.example.com"),
			},
		},
	})
}

func TestDomainResource_Validation(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	for _, name := range []string{"Example.com", "\u00c9xample.com", "localhost", ".example.com", "example.com."} {
		runUnitTest(t, f, []testStep{{
			config:      `resource "definednet_domain" "d" { domain_name = "` + name + `" }`,
			expectError: "must be a lowercase domain name",
		}})
	}
}

func TestDomainResource_RemovedOutOfBand(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	runRemovedOutOfBandTest(t, f, `
resource "definednet_domain" "d" {
  domain_name = "example.com"
}`, "definednet_domain.d", func() { clear(f.domains) })
}

const domainVerificationConfig = `
resource "definednet_domain" "d" {
  domain_name = "example.com"
}

resource "definednet_domain_verification" "d" {
  domain_id = definednet_domain.d.id
}
`

func TestDomainVerificationResource(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	verifyPollInterval = time.Millisecond
	// Two failed lookups before the record "propagates" exercises the retry loop.
	f.domainVerifyFailures = 2

	runUnitTest(t, f, []testStep{
		{
			config: domainVerificationConfig,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrPair("definednet_domain_verification.d", "id", "definednet_domain.d", "id"),
				resource.TestCheckResourceAttrPair("definednet_domain_verification.d", "domain_id", "definednet_domain.d", "id"),
				func(*terraform.State) error {
					if f.domainVerifyFailures != 0 {
						return fmt.Errorf("expected every failing verify attempt to be consumed, %d left", f.domainVerifyFailures)
					}
					return nil
				},
			},
		},
		{importState: true, importResource: "definednet_domain_verification.d"},
		{
			// The domain refreshes to verified on the next plan with no diff.
			config: domainVerificationConfig,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_domain.d", "verified", "true"),
			},
		},
	})
}

// A verification recreated under an existing domain must plan a known id, or a
// downstream reference to it would be replaced along with it.
func TestDomainVerificationResource_Unverified(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	verifyPollInterval = time.Millisecond

	cfg := providerConfig(f) + domainVerificationConfig
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		Steps: []resource.TestStep{
			{Config: cfg},
			{
				PreConfig: func() {
					f.mu.Lock()
					defer f.mu.Unlock()
					for _, d := range f.domains {
						d.IsVerified = false
					}
				},
				Config: cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: append(
					expectCreate("definednet_domain_verification.d"),
					plancheck.ExpectKnownValue("definednet_domain_verification.d", tfjsonpath.New("id"), knownvalue.NotNull()),
				)},
			},
		},
	})
}

func TestDomainVerificationResource_Timeout(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	verifyPollInterval = time.Millisecond
	f.domainVerifyFailures = 1 << 30

	runUnitTest(t, f, []testStep{{
		config: `
resource "definednet_domain" "d" {
  domain_name = "example.com"
}

resource "definednet_domain_verification" "d" {
  domain_id = definednet_domain.d.id
  timeouts { create = "100ms" }
}`,
		expectError: `(?s)timed out waiting for TXT record.*ERR_DOMAIN_VERIFICATION_FAILED_NXDOMAIN`,
	}})
}

func TestDomainVerificationResource_ServerError(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	verifyPollInterval = time.Millisecond
	// The API answers 500 for resolver failures other than NXDOMAIN; the client
	// never retries a POST, so the poll loop has to.
	f.domainVerifyFailures = 2
	f.domainVerifyFailCode = "ERR_INTERNAL"
	f.domainVerifyFailStatus = 500

	runUnitTest(t, f, []testStep{{
		config: domainVerificationConfig,
		checks: []resource.TestCheckFunc{
			resource.TestCheckResourceAttrPair("definednet_domain_verification.d", "id", "definednet_domain.d", "id"),
		},
	}})
}

func TestDomainVerificationResource_InUse(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	verifyPollInterval = time.Millisecond
	// One fatal failure: a retry would succeed, so an error proves it was not retried.
	f.domainVerifyFailures = 1
	f.domainVerifyFailCode = "ERR_DOMAIN_VERIFICATION_FAILURE_IN_USE"

	runUnitTest(t, f, []testStep{{
		config:      domainVerificationConfig,
		expectError: "ERR_DOMAIN_VERIFICATION_FAILURE_IN_USE",
	}})
}

func TestDomainVerificationResource_Interrupted(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	verifyPollInterval = time.Millisecond
	f.domainVerifyFailures = 1 << 30

	c, err := client.New(f.URL(), f.apiKey)
	if err != nil {
		t.Fatal(err)
	}
	d, err := c.CreateDomain(context.Background(), client.DomainCreateRequest{DomainName: "example.com"})
	if err != nil {
		t.Fatal(err)
	}

	// Terraform cancels the apply context on interrupt; the deadline is still far off.
	parent, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	ctx, cancelTimeout := context.WithTimeout(parent, time.Minute)
	defer cancelTimeout()

	err = (&domainVerificationResource{client: c}).verify(ctx, d.ID)
	if !errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "timed out") {
		t.Fatalf("expected a plain cancellation, got %v", err)
	}
}
