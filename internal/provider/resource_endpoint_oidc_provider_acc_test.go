package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

// The API only fetches the issuer's discovery document and never contacts it
// with the client credentials, so any public issuer and made-up client work.
const accIssuer = "https://accounts.google.com"

func accOIDCBase(network, role string) string {
	return fmt.Sprintf(`
resource "definednet_network" "n" {
  name      = %q
  ipv4_cidr = "192.168.140.0/22"
}

resource "definednet_role" "r" {
  name = %q
}
`, network, role)
}

func TestAccEndpointOIDCProviderResource(t *testing.T) {
	// The domain stays in every step. Dropping it in the same apply that
	// detaches it lets Terraform delete it first, which the API refuses with
	// ERR_HAS_DEPENDENTS because the provider still holds it.
	base := accOIDCBase(accName(), accName()) + fmt.Sprintf(`
resource "definednet_domain" "d" {
  domain_name = %q
}

resource "definednet_domain_verification" "d" {
  domain_id = definednet_domain.d.id
}
`, accDomain())
	name, network2 := accName(), accName()
	update := base + fmt.Sprintf(`
resource "definednet_endpoint_oidc_provider" "p" {
  name          = "%s-renamed"
  client_id     = "tf-acc-client"
  client_secret = "secret-2"
  issuer_url    = %q
  network_id    = definednet_network.n.id
}
`, name, accIssuer)
	moved := base + fmt.Sprintf(`
resource "definednet_network" "m" {
  name      = %q
  ipv4_cidr = "192.168.144.0/22"
}

resource "definednet_endpoint_oidc_provider" "p" {
  name          = "%s-renamed"
  client_id     = "tf-acc-client"
  client_secret = "secret-2"
  issuer_url    = %q
  network_id    = definednet_network.m.id
}
`, network2, name, accIssuer)
	runAccTest(t, []testStep{
		{
			config: base + fmt.Sprintf(`
resource "definednet_endpoint_oidc_provider" "p" {
  name                = %q
  client_id           = "tf-acc-client"
  client_secret       = "secret-1"
  issuer_url          = %q
  enabled             = true
  network_id          = definednet_network.n.id
  role_id             = definednet_role.r.id
  auth_validity_hours = 168
  domain_id           = definednet_domain_verification.d.domain_id
  auto_assign_cidrs   = [definednet_network.n.ipv4_cidr]
}
`, name, accIssuer),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrSet("definednet_endpoint_oidc_provider.p", "id"),
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "enabled", "true"),
				resource.TestCheckResourceAttrPair("definednet_endpoint_oidc_provider.p", "domain_id", "definednet_domain.d", "id"),
				// The API adds the network's IPv6 prefix; state holds only the IPv4 opt-in.
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "auto_assign_cidrs.#", "1"),
				resource.TestCheckTypeSetElemAttr("definednet_endpoint_oidc_provider.p", "auto_assign_cidrs.*", "192.168.140.0/22"),
			},
		},
		{
			// The API cannot return the secret, so it is null after import.
			importState: true, importResource: "definednet_endpoint_oidc_provider.p",
			importVerifyIgnore: []string{"client_secret"},
		},
		{
			// Omitting auto_assign_cidrs keeps the IPv4 opt-in the API holds.
			config:     update,
			planChecks: expectUpdate("definednet_endpoint_oidc_provider.p"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "enabled", "false"),
				resource.TestCheckNoResourceAttr("definednet_endpoint_oidc_provider.p", "role_id"),
				resource.TestCheckNoResourceAttr("definednet_endpoint_oidc_provider.p", "domain_id"),
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "auto_assign_cidrs.#", "1"),
			},
		},
		{
			// The old network's IPv4 opt-in must not follow the provider to a
			// network that would reject it.
			config:     moved,
			planChecks: expectUpdate("definednet_endpoint_oidc_provider.p"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrPair("definednet_endpoint_oidc_provider.p", "network_id", "definednet_network.m", "id"),
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "auto_assign_cidrs.#", "0"),
			},
		},
	})
}

func TestAccEndpointOIDCProviderResource_WriteOnly(t *testing.T) {
	base := accOIDCBase(accName(), accName())
	name := accName()
	cfg := func(secret string, version int) string {
		return base + fmt.Sprintf(`
resource "definednet_endpoint_oidc_provider" "p" {
  name                     = %q
  client_id                = "tf-acc-client"
  client_secret_wo         = %q
  client_secret_wo_version = %d
  issuer_url               = %q
  network_id               = definednet_network.n.id
}
`, name, secret, version, accIssuer)
	}
	runAccTest(t, []testStep{
		{
			config: cfg("secret-1", 1),
			checks: []resource.TestCheckFunc{
				resource.TestCheckNoResourceAttr("definednet_endpoint_oidc_provider.p", "client_secret_wo"),
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "client_secret_wo_version", "1"),
			},
		},
		// A rotated secret without a version bump is invisible to Terraform.
		{config: cfg("secret-2", 1)},
		{
			config:     cfg("secret-2", 2),
			planChecks: expectUpdate("definednet_endpoint_oidc_provider.p"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "client_secret_wo_version", "2"),
			},
		},
	})
}

func TestAccEndpointOIDCProviderResource_RemovedOutOfBand(t *testing.T) {
	runAccRemovedOutOfBandTest(t, accOIDCBase(accName(), accName())+fmt.Sprintf(`
resource "definednet_endpoint_oidc_provider" "p" {
  name          = %q
  client_id     = "tf-acc-client"
  client_secret = "secret"
  issuer_url    = %q
  network_id    = definednet_network.n.id
}`, accName(), accIssuer), "definednet_endpoint_oidc_provider.p", func(c *client.Client, id string) error {
		return c.DeleteEndpointOIDCProvider(context.Background(), id)
	})
}

// With create_before_destroy on the verification, one apply can detach the
// domain and delete it: the provider is updated before the domain is destroyed.
func TestAccEndpointOIDCProviderResource_DetachAndDeleteDomain(t *testing.T) {
	base := accOIDCBase(accName(), accName())
	name := accName()
	provider := func(domainID string) string {
		return fmt.Sprintf(`
resource "definednet_endpoint_oidc_provider" "p" {
  name          = %q
  client_id     = "tf-acc-client"
  client_secret = "secret"
  issuer_url    = %q
  network_id    = definednet_network.n.id
  %s
}
`, name, accIssuer, domainID)
	}
	runAccTest(t, []testStep{
		{
			config: base + fmt.Sprintf(`
resource "definednet_domain" "d" {
  domain_name = %q
}

resource "definednet_domain_verification" "d" {
  domain_id = definednet_domain.d.id
  lifecycle { create_before_destroy = true }
}
`, accDomain()) + provider("domain_id = definednet_domain_verification.d.domain_id"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrPair("definednet_endpoint_oidc_provider.p", "domain_id", "definednet_domain.d", "id"),
			},
		},
		{
			config: base + provider(""),
			checks: []resource.TestCheckFunc{
				resource.TestCheckNoResourceAttr("definednet_endpoint_oidc_provider.p", "domain_id"),
			},
		},
	})
}
