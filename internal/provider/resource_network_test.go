package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestNetworkResource(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	v6only := `
resource "definednet_network" "n" {
  name = "Network1"
}
`
	addV4 := `
resource "definednet_network" "n" {
  name                  = "Network1 renamed"
  description           = "primary"
  ipv4_cidr             = "100.100.0.0/22"
  lighthouses_as_relays = true
}
`
	changeV4 := `
resource "definednet_network" "n" {
  name      = "Network1 renamed"
  ipv4_cidr = "100.101.0.0/22"
}
`
	runUnitTest(t, f, []testStep{
		{
			config: v6only,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrSet("definednet_network.n", "id"),
				resource.TestCheckNoResourceAttr("definednet_network.n", "ipv4_cidr"),
				resource.TestCheckResourceAttr("definednet_network.n", "cidrs.#", "1"),
				resource.TestCheckResourceAttr("definednet_network.n", "cert_version", "2"),
				resource.TestCheckResourceAttr("definednet_network.n", "curve", "25519"),
				resource.TestCheckResourceAttr("definednet_network.n", "lighthouses_as_relays", "false"),
				resource.TestCheckResourceAttr("definednet_network.n", "disable_managed_lighthouses", "false"),
				resource.TestCheckResourceAttrSet("definednet_network.n", "created_at"),
			},
		},
		{importState: true, importResource: "definednet_network.n"},
		{
			// Adding an IPv4 prefix to a v6-only network is an in-place update.
			config:     addV4,
			planChecks: expectUpdate("definednet_network.n"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_network.n", "name", "Network1 renamed"),
				resource.TestCheckResourceAttr("definednet_network.n", "ipv4_cidr", "100.100.0.0/22"),
				resource.TestCheckResourceAttr("definednet_network.n", "cidrs.#", "2"),
				resource.TestCheckResourceAttr("definednet_network.n", "cidrs.0", "100.100.0.0/22"),
				resource.TestCheckResourceAttr("definednet_network.n", "lighthouses_as_relays", "true"),
			},
		},
		{
			// Changing an existing IPv4 prefix replaces the network.
			config:     changeV4,
			planChecks: expectReplace("definednet_network.n"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_network.n", "ipv4_cidr", "100.101.0.0/22"),
				resource.TestCheckResourceAttr("definednet_network.n", "description", ""),
			},
		},
	})
}

func TestNetworkResource_MissingScope(t *testing.T) {
	f := newFakeAPI()
	f.missingScopes = map[string]bool{"networks:create": true}
	defer f.Close()

	runUnitTest(t, f, []testStep{{
		config: `
resource "definednet_network" "n" {
  name = "nope"
}`,
		expectError: "(?s)HTTP 403.*networks:create",
	}})
}

func TestNetworkDataSource(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	cfg := `
resource "definednet_network" "a" {
  name      = "alpha"
  ipv4_cidr = "10.1.0.0/16"
}

resource "definednet_network" "b" {
  name = "beta"
}

data "definednet_network" "by_name" {
  name       = "alpha"
  depends_on = [definednet_network.a, definednet_network.b]
}

data "definednet_network" "by_id" {
  id = definednet_network.b.id
}
`
	runUnitTest(t, f, []testStep{
		// Invalid configurations come first so the final step leaves a valid
		// configuration for the post-test destroy.
		{
			config: `
data "definednet_network" "x" {
}`,
			expectError: "Exactly one of these attributes must be configured",
		},
		{
			config: `
data "definednet_network" "x" {
  name = "missing"
}`,
			expectError: "Network not found",
		},
		{
			config: cfg,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrPair("data.definednet_network.by_name", "id", "definednet_network.a", "id"),
				resource.TestCheckResourceAttr("data.definednet_network.by_name", "ipv4_cidr", "10.1.0.0/16"),
				resource.TestCheckResourceAttr("data.definednet_network.by_id", "name", "beta"),
				resource.TestCheckNoResourceAttr("data.definednet_network.by_id", "ipv4_cidr"),
			},
		},
	})
}
