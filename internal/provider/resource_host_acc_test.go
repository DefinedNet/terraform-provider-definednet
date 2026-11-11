package provider

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

func accHostBase() string {
	return fmt.Sprintf(`
resource "definednet_network" "n" {
  name      = %q
  ipv4_cidr = "192.168.152.0/22"
}

resource "definednet_role" "r" {
  name = %q
}
`, accName(), accName())
}

func TestAccHostResource(t *testing.T) {
	base := accHostBase()
	name, tag := accName(), accTagName()
	lighthouse := base + fmt.Sprintf(`
resource "definednet_host" "lh" {
  network_id       = definednet_network.n.id
  name             = %q
  role_id          = definednet_role.r.id
  is_lighthouse    = true
  ipv4_address     = "192.168.152.10"
  static_addresses = ["203.0.113.10:4242", "lh.example.com:4242"]
  listen_port      = 4242
  tags             = [%q]
  config_overrides = [
    { key = "lighthouse.serve_dns", value = jsonencode(true) },
  ]
}

resource "definednet_host" "pet" {
  network_id               = definednet_network.n.id
  name                     = "%s-pet"
  enrollment_code_triggers = { gen = "1" }
}
`, name, tag, name)
	updated := strings.NewReplacer(
		`"203.0.113.10:4242", "lh.example.com:4242"`, `"203.0.113.11:4243"`,
		"listen_port      = 4242", "listen_port      = 4243",
		"role_id          = definednet_role.r.id\n", "",
		`{ gen = "1" }`, `{ gen = "2" }`,
	).Replace(lighthouse)
	// Every code in state is freshly minted: a trigger change must not keep the
	// old one. The API offers no key-accessible way to check a code is live.
	var codes []string
	liveCode := func(addr string) resource.TestCheckFunc {
		return func(s *terraform.State) error {
			code := s.RootModule().Resources[addr].Primary.Attributes["enrollment_code"]
			if code == "" || slices.Contains(codes, code) {
				return fmt.Errorf("%s: enrollment_code %q is empty or was minted before", addr, code)
			}
			codes = append(codes, code)
			return nil
		}
	}
	runAccTest(t, []testStep{
		{
			config: lighthouse,
			checks: []resource.TestCheckFunc{
				resource.TestMatchResourceAttr("definednet_host.lh", "id", regexp.MustCompile(`^host-`)),
				resource.TestCheckResourceAttr("definednet_host.lh", "ipv4_address", "192.168.152.10"),
				resource.TestCheckResourceAttr("definednet_host.lh", "static_addresses.#", "2"),
				resource.TestCheckResourceAttr("definednet_host.lh", "is_blocked", "false"),
				// The API assigns the pet an address from the network's IPv4 prefix.
				resource.TestMatchResourceAttr("definednet_host.pet", "ipv4_address", regexp.MustCompile(`^192\.168\.15[2-5]\.`)),
				liveCode("definednet_host.lh"),
				liveCode("definednet_host.pet"),
			},
		},
		{importState: true, importResource: "definednet_host.lh", importVerifyIgnore: []string{"enrollment_code"}},
		{importState: true, importResource: "definednet_host.pet", importVerifyIgnore: []string{"enrollment_code"}},
		{
			config:     updated,
			planChecks: expectUpdate("definednet_host.lh"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckNoResourceAttr("definednet_host.lh", "role_id"),
				resource.TestCheckResourceAttr("definednet_host.lh", "listen_port", "4243"),
				resource.TestCheckResourceAttr("definednet_host.lh", "static_addresses.#", "1"),
				liveCode("definednet_host.pet"),
			},
		},
		{
			config:     strings.Replace(updated, `"192.168.152.10"`, `"192.168.152.11"`, 1),
			planChecks: expectReplace("definednet_host.lh"),
			checks:     []resource.TestCheckFunc{resource.TestCheckResourceAttr("definednet_host.lh", "ipv4_address", "192.168.152.11")},
		},
	})
}

// A host on an IPv6-only network gets an IPv4 address in place once the
// network has an IPv4 prefix.
func TestAccHostResource_AddIPv4(t *testing.T) {
	network, name := accName(), accName()
	cfg := func(cidr, addr string) string {
		return fmt.Sprintf(`
resource "definednet_network" "n" {
  name = %q
  %s
}

resource "definednet_host" "h" {
  network_id = definednet_network.n.id
  name       = %q
  %s
}
`, network, cidr, name, addr)
	}
	const cidr = `ipv4_cidr = "192.168.156.0/22"`
	runAccTest(t, []testStep{
		{
			config: cfg("", ""),
			checks: []resource.TestCheckFunc{resource.TestCheckNoResourceAttr("definednet_host.h", "ipv4_address")},
		},
		{
			config:     cfg(cidr, ""),
			planChecks: expectUpdate("definednet_network.n"),
			checks:     []resource.TestCheckFunc{resource.TestCheckNoResourceAttr("definednet_host.h", "ipv4_address")},
		},
		{
			config:     cfg(cidr, `ipv4_address = "192.168.156.5"`),
			planChecks: expectUpdate("definednet_host.h"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_host.h", "ipv4_address", "192.168.156.5"),
				resource.TestCheckResourceAttr("definednet_host.h", "ip_addresses.#", "2"),
			},
		},
	})
}

func TestAccHostResource_RemovedOutOfBand(t *testing.T) {
	runAccRemovedOutOfBandTest(t, accHostBase()+fmt.Sprintf(`
resource "definednet_host" "h" {
  network_id = definednet_network.n.id
  name       = %q
}`, accName()), "definednet_host.h", func(c *client.Client, id string) error {
		return c.DeleteHost(context.Background(), id)
	})
}
