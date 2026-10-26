package provider

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

// oidcBase creates the network, verified domain and role every provider test needs.
const oidcBase = `
resource "definednet_network" "n" {
  name      = "n"
  ipv4_cidr = "10.10.0.0/16"
}

resource "definednet_role" "r" {
  name = "r"
}

resource "definednet_domain" "d" {
  domain_name = "example.com"
}

resource "definednet_domain_verification" "d" {
  domain_id = definednet_domain.d.id
}
`

// secretOf returns the fake's current secret for the only provider.
func secretOf(f *fakeAPI) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for id := range f.oidc {
		return f.oidcSecrets[id]
	}
	return ""
}

func expectSecret(f *fakeAPI, want string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if got := secretOf(f); got != want {
			return fmt.Errorf("API holds secret %q, want %q", got, want)
		}
		return nil
	}
}

// onlyOIDC returns the fake's only provider for out-of-band edits and assertions.
func onlyOIDC(f *fakeAPI) *client.EndpointOIDCProvider {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, p := range f.oidc {
		return p
	}
	return nil
}

func expectAutoAssign(f *fakeAPI, want ...string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		got := onlyOIDC(f).AutoAssignCIDRs
		if !slices.Equal(got, want) {
			return fmt.Errorf("API holds autoAssignCIDRs %v, want %v", got, want)
		}
		return nil
	}
}

func TestEndpointOIDCProviderResource(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	verifyPollInterval = time.Millisecond

	create := oidcBase + `
resource "definednet_endpoint_oidc_provider" "p" {
  name                = "Okta"
  client_id           = "client-1"
  client_secret       = "hunter2"
  issuer_url          = "https://corp.okta.com"
  enabled             = true
  network_id          = definednet_network.n.id
  role_id             = definednet_role.r.id
  auth_validity_hours = 168
  domain_id           = definednet_domain_verification.d.domain_id
  auto_assign_cidrs   = [definednet_network.n.ipv4_cidr]
}
`
	update := oidcBase + `
resource "definednet_endpoint_oidc_provider" "p" {
  name          = "Okta renamed"
  client_id     = "client-1"
  client_secret = "hunter3"
  issuer_url    = "https://corp.okta.com"
  network_id    = definednet_network.n.id
}
`
	moved := strings.Replace(update, "network_id    = definednet_network.n.id", "network_id    = definednet_network.m.id", 1) + `
resource "definednet_network" "m" {
  name      = "m"
  ipv4_cidr = "10.20.0.0/16"
}
`
	runUnitTest(t, f, []testStep{
		{
			config: create,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrSet("definednet_endpoint_oidc_provider.p", "id"),
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "enabled", "true"),
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "auth_validity_hours", "168"),
				resource.TestCheckResourceAttrPair("definednet_endpoint_oidc_provider.p", "domain_id", "definednet_domain.d", "id"),
				// The API adds the network's IPv6 prefix; state holds only the IPv4 opt-in.
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "auto_assign_cidrs.#", "1"),
				resource.TestCheckTypeSetElemAttr("definednet_endpoint_oidc_provider.p", "auto_assign_cidrs.*", "10.10.0.0/16"),
				expectAutoAssign(f, "10.10.0.0/16", "fd00:1234:5678:1::/80"),
				resource.TestCheckNoResourceAttr("definednet_endpoint_oidc_provider.p", "client_secret_wo"),
				expectSecret(f, "hunter2"),
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
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "name", "Okta renamed"),
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "enabled", "false"),
				resource.TestCheckNoResourceAttr("definednet_endpoint_oidc_provider.p", "role_id"),
				resource.TestCheckNoResourceAttr("definednet_endpoint_oidc_provider.p", "domain_id"),
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "auto_assign_cidrs.#", "1"),
				expectAutoAssign(f, "10.10.0.0/16", "fd00:1234:5678:1::/80"),
				expectSecret(f, "hunter3"),
			},
		},
		{
			// Moving to another network with the attribute omitted must not carry the
			// old network's IPv4 CIDR, which the new network rejects; the API's default
			// for the new network applies (IPv6 only on a dual-stack network).
			config:     moved,
			planChecks: expectUpdate("definednet_endpoint_oidc_provider.p"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrPair("definednet_endpoint_oidc_provider.p", "network_id", "definednet_network.m", "id"),
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "auto_assign_cidrs.#", "0"),
			},
		},
		{
			// An explicit empty set declines IPv4; the API stores IPv6 only.
			config: moved + `
resource "definednet_endpoint_oidc_provider" "q" {
  name              = "no v4"
  client_id         = "client-2"
  client_secret     = "s"
  issuer_url        = "https://corp.okta.com"
  network_id        = definednet_network.n.id
  auto_assign_cidrs = []
}`,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.q", "auto_assign_cidrs.#", "0"),
			},
		},
	})
}

// The IPv4 opt-in is removed outside Terraform; the next plan shows the
// removal and apply restores it.
func TestEndpointOIDCProviderResource_AutoAssignDrift(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	verifyPollInterval = time.Millisecond

	cfg := oidcBase + `
resource "definednet_endpoint_oidc_provider" "p" {
  name              = "p"
  client_id         = "c"
  client_secret     = "s"
  issuer_url        = "https://idp.example.com"
  network_id        = definednet_network.n.id
  auto_assign_cidrs = [definednet_network.n.ipv4_cidr]
}`
	runUnitTest(t, f, []testStep{
		{config: cfg, checks: []resource.TestCheckFunc{expectAutoAssign(f, "10.10.0.0/16", "fd00:1234:5678:1::/80")}},
		{
			preConfig:  func() { onlyOIDC(f).AutoAssignCIDRs = []string{"fd00:1234:5678:1::/80"} },
			config:     cfg,
			planChecks: expectUpdate("definednet_endpoint_oidc_provider.p"),
			checks:     []resource.TestCheckFunc{expectAutoAssign(f, "10.10.0.0/16", "fd00:1234:5678:1::/80")},
		},
	})
}

func TestEndpointOIDCProviderResource_WriteOnly(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	verifyPollInterval = time.Millisecond

	cfg := func(secret string, version int) string {
		return oidcBase + fmt.Sprintf(`
resource "definednet_endpoint_oidc_provider" "p" {
  name                     = "Okta"
  client_id                = "client-1"
  client_secret_wo         = %q
  client_secret_wo_version = %d
  issuer_url               = "https://corp.okta.com"
  network_id               = definednet_network.n.id
}
`, secret, version)
	}
	runUnitTest(t, f, []testStep{
		{
			config: cfg("hunter2", 1),
			checks: []resource.TestCheckFunc{
				resource.TestCheckNoResourceAttr("definednet_endpoint_oidc_provider.p", "client_secret_wo"),
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "client_secret_wo_version", "1"),
				expectSecret(f, "hunter2"),
			},
		},
		{
			// A rotated secret without a version bump is invisible to Terraform: no plan, API unchanged.
			config: cfg("rotated", 1),
			checks: []resource.TestCheckFunc{expectSecret(f, "hunter2")},
		},
		{
			config:     cfg("rotated", 2),
			planChecks: expectUpdate("definednet_endpoint_oidc_provider.p"),
			checks:     []resource.TestCheckFunc{expectSecret(f, "rotated")},
		},
		{
			// Switching to the stored variant is an ordinary update.
			config: oidcBase + `
resource "definednet_endpoint_oidc_provider" "p" {
  name          = "Okta"
  client_id     = "client-1"
  client_secret = "stored"
  issuer_url    = "https://corp.okta.com"
  network_id    = definednet_network.n.id
}
`,
			planChecks: expectUpdate("definednet_endpoint_oidc_provider.p"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckNoResourceAttr("definednet_endpoint_oidc_provider.p", "client_secret_wo_version"),
				expectSecret(f, "stored"),
			},
		},
	})
}

func TestEndpointOIDCProviderResource_Validation(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	base := `
resource "definednet_endpoint_oidc_provider" "p" {
  name       = "p"
  client_id  = "c"
  network_id = "network-X"
`
	for _, tc := range []struct{ body, want string }{
		{`client_secret = "a"
client_secret_wo = "b"
client_secret_wo_version = 1`, `one \(and only one\) of`},
		{``, `one \(and only one\) of`},
		{`client_secret_wo = "b"`, `client_secret_wo_version" must be specified when`},
		{`client_secret = "a"
enabled = true`, "domain_id must be set when enabled is true"},
		{`client_secret = "a"
auto_assign_cidrs = ["10.0.0.1"]`, "must be an IPv4 network"},
		{`client_secret = "a"
auto_assign_cidrs = ["fd00::/64"]`, "must be an IPv4 network"},
		{`client_secret = "a"
issuer_url = "http://idp.example.com"`, "must be an https URL"},
		{`client_secret = "a"
auth_validity_hours = 0`, "value must be between 1 and 43800"},
	} {
		if !strings.Contains(tc.body, "issuer_url") {
			tc.body += "\nissuer_url = \"https://idp.example.com\""
		}
		runUnitTest(t, f, []testStep{{config: base + tc.body + "\n}", expectError: tc.want}})
	}
}

func TestEndpointOIDCProviderResource_APIErrors(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	// Enabled against an unverified domain reaches the API and comes back with the hint.
	runUnitTest(t, f, []testStep{{
		config: `
resource "definednet_network" "n" {
  name      = "n"
  ipv4_cidr = "10.10.0.0/16"
}

resource "definednet_domain" "d" {
  domain_name = "example.com"
}

resource "definednet_endpoint_oidc_provider" "p" {
  name          = "p"
  client_id     = "c"
  client_secret = "s"
  issuer_url    = "https://idp.example.com"
  enabled       = true
  network_id    = definednet_network.n.id
  domain_id     = definednet_domain.d.id
}`,
		expectError: "Verify the domain first",
	}})
}

func TestEndpointOIDCProviderResource_SubPrefixRejected(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	runUnitTest(t, f, []testStep{{
		config: `
resource "definednet_network" "n" {
  name      = "n"
  ipv4_cidr = "10.10.0.0/16"
}

resource "definednet_endpoint_oidc_provider" "p" {
  name              = "p"
  client_id         = "c"
  client_secret     = "s"
  issuer_url        = "https://idp.example.com"
  network_id        = definednet_network.n.id
  auto_assign_cidrs = ["10.10.5.0/24"]
}`,
		expectError: "ERR_OUT_OF_RANGE",
	}})
}

func TestEndpointOIDCProviderResource_RemovedOutOfBand(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	verifyPollInterval = time.Millisecond

	runRemovedOutOfBandTest(t, f, oidcBase+`
resource "definednet_endpoint_oidc_provider" "p" {
  name          = "p"
  client_id     = "c"
  client_secret = "s"
  issuer_url    = "https://idp.example.com"
  network_id    = definednet_network.n.id
}`, "definednet_endpoint_oidc_provider.p", func() { clear(f.oidc) })
}

// A provider created outside Terraform with IPv4 opted in is imported, then
// updated from that imported state: the first apply must re-send the secret
// because import cannot recover it, and must keep the IPv4 opt-in even though
// the config does not mention it.
func TestEndpointOIDCProviderResource_ImportThenUpdate(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	c, err := client.New(f.URL(), f.apiKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	n, err := c.CreateNetwork(ctx, client.NetworkCreateRequest{Name: "n", CIDRs: []string{"10.10.0.0/16"}})
	if err != nil {
		t.Fatal(err)
	}
	secret := "from-the-ui"
	p, err := c.CreateEndpointOIDCProvider(ctx, client.EndpointOIDCProviderRequest{
		Name: "Okta", ClientID: "client-1", ClientSecret: &secret, IssuerURL: "https://corp.okta.com", NetworkID: n.ID,
		AutoAssignCIDRs: []string{"10.10.0.0/16"},
	})
	if err != nil {
		t.Fatal(err)
	}

	cfg := fmt.Sprintf(`
resource "definednet_endpoint_oidc_provider" "p" {
  name                     = "Okta"
  client_id                = "client-1"
  client_secret_wo         = "from-terraform"
  client_secret_wo_version = 1
  issuer_url               = "https://corp.okta.com"
  network_id               = %q
}
`, n.ID)
	runUnitTest(t, f, []testStep{
		{
			config: cfg, importState: true, importPersist: true,
			importResource: "definednet_endpoint_oidc_provider.p", importStateID: p.ID,
		},
		{
			config:     cfg,
			planChecks: expectUpdate("definednet_endpoint_oidc_provider.p"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "id", p.ID),
				resource.TestCheckResourceAttr("definednet_endpoint_oidc_provider.p", "auto_assign_cidrs.#", "1"),
				expectSecret(f, "from-terraform"),
				expectAutoAssign(f, "10.10.0.0/16", "fd00:1234:5678:1::/80"),
			},
		},
	})
}
