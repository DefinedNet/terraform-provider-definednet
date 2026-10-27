package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

// expectAPINetworkOverrides checks the overrides the API holds, independent of state.
func expectAPINetworkOverrides(addr string, want int) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		c, err := testAccClient()
		if err != nil {
			return err
		}
		got, err := c.GetNetworkConfigOverrides(context.Background(), s.RootModule().Resources[addr].Primary.ID)
		if err != nil {
			return err
		}
		if len(got) != want {
			return fmt.Errorf("API holds %d config overrides %v, want %d", len(got), got, want)
		}
		return nil
	}
}

func TestAccNetworkResource(t *testing.T) {
	name := accName()
	v6only := fmt.Sprintf(`
resource "definednet_network" "n" {
  name = %q

  config_overrides = [
    { key = "punchy.delay", value = jsonencode("200ms") },
    { key = "lighthouse.local_allow_list", value = jsonencode({ interfaces = { "docker.*" = false, "br-.*" = false } }) },
  ]
}
`, name)
	addV4 := fmt.Sprintf(`
resource "definednet_network" "n" {
  name                  = "%s-renamed"
  description           = "primary"
  ipv4_cidr             = "192.168.128.0/22"
  lighthouses_as_relays = false

  config_overrides = [
    { key = "listen.udp_offloads", value = jsonencode(true) },
  ]
}
`, name)
	changeV4 := fmt.Sprintf(`
resource "definednet_network" "n" {
  name      = "%s-renamed"
  ipv4_cidr = "192.168.132.0/22"

  config_overrides = [
    { key = "listen.udp_offloads", value = jsonencode(true) },
  ]
}
`, name)
	runAccTest(t, []testStep{
		{
			config: v6only,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrSet("definednet_network.n", "id"),
				resource.TestCheckNoResourceAttr("definednet_network.n", "ipv4_cidr"),
				resource.TestCheckResourceAttr("definednet_network.n", "cidrs.#", "1"),
				resource.TestCheckResourceAttr("definednet_network.n", "config_overrides.#", "2"),
				expectAPINetworkOverrides("definednet_network.n", 2),
			},
		},
		// The API may return object values with keys in any order; import
		// must canonicalize them to match the jsonencode() text.
		{importState: true, importResource: "definednet_network.n"},
		{
			config:     addV4,
			planChecks: expectUpdate("definednet_network.n"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_network.n", "ipv4_cidr", "192.168.128.0/22"),
				resource.TestCheckResourceAttr("definednet_network.n", "cidrs.#", "2"),
				resource.TestCheckResourceAttr("definednet_network.n", "description", "primary"),
				resource.TestCheckResourceAttr("definednet_network.n", "lighthouses_as_relays", "false"),
				resource.TestCheckResourceAttr("definednet_network.n", "config_overrides.#", "1"),
			},
		},
		{importState: true, importResource: "definednet_network.n"},
		{
			config:     changeV4,
			planChecks: expectReplace("definednet_network.n"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_network.n", "ipv4_cidr", "192.168.132.0/22"),
				resource.TestCheckResourceAttr("definednet_network.n", "description", ""),
			},
		},
	})
}

// The API seeds every new network with a generated tun.dev override, so the
// three spellings of config_overrides behave differently.
func TestAccNetworkResource_ServerManagedOverrides(t *testing.T) {
	name := accName()
	cfg := func(overrides string) string {
		return fmt.Sprintf(`
resource "definednet_network" "n" {
  name = %q
  %s
}
`, name, overrides)
	}
	omitted := cfg("")
	runAccTest(t, []testStep{
		{
			// Omitted: the generated tun.dev is read into state and the
			// post-apply plan is empty.
			config: omitted,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_network.n", "config_overrides.#", "1"),
				resource.TestCheckTypeSetElemNestedAttrs("definednet_network.n", "config_overrides.*", map[string]string{"key": "tun.dev"}),
				expectAPINetworkOverrides("definednet_network.n", 1),
			},
		},
		{
			config: cfg(`config_overrides = [{ key = "punchy.delay", value = jsonencode("200ms") }]`),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_network.n", "config_overrides.#", "1"),
				resource.TestCheckTypeSetElemNestedAttrs("definednet_network.n", "config_overrides.*", map[string]string{"key": "punchy.delay"}),
				expectAPINetworkOverrides("definednet_network.n", 1),
			},
		},
		{
			config: cfg(`config_overrides = []`),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_network.n", "config_overrides.#", "0"),
				expectAPINetworkOverrides("definednet_network.n", 0),
			},
		},
		{
			// Omitted again: the API does not re-seed tun.dev after a PUT.
			config: omitted,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_network.n", "config_overrides.#", "0"),
				expectAPINetworkOverrides("definednet_network.n", 0),
			},
		},
	})
}

func TestAccNetworkResource_RemovedOutOfBand(t *testing.T) {
	runAccRemovedOutOfBandTest(t, fmt.Sprintf(`
resource "definednet_network" "n" {
  name = %q
}`, accName()), "definednet_network.n", func(c *client.Client, id string) error {
		return c.DeleteNetwork(context.Background(), id)
	})
}

func TestAccNetworkDataSource(t *testing.T) {
	a, b := accName(), accName()
	runAccTest(t, []testStep{{
		config: fmt.Sprintf(`
resource "definednet_network" "a" {
  name      = %q
  ipv4_cidr = "192.168.136.0/22"

  config_overrides = [
    { key = "tun.use_offloads", value = jsonencode(true) },
  ]
}

resource "definednet_network" "b" {
  name = %q
}

data "definednet_network" "by_name" {
  name       = %q
  depends_on = [definednet_network.a, definednet_network.b]
}

data "definednet_network" "by_id" {
  id = definednet_network.b.id
}
`, a, b, a),
		checks: []resource.TestCheckFunc{
			resource.TestCheckResourceAttrPair("data.definednet_network.by_name", "id", "definednet_network.a", "id"),
			resource.TestCheckResourceAttr("data.definednet_network.by_name", "ipv4_cidr", "192.168.136.0/22"),
			resource.TestCheckResourceAttr("data.definednet_network.by_name", "config_overrides.#", "1"),
			resource.TestCheckResourceAttr("data.definednet_network.by_name", "config_overrides.0.value", "true"),
			resource.TestCheckResourceAttr("data.definednet_network.by_id", "name", b),
			resource.TestCheckResourceAttrPair("data.definednet_network.by_id", "config_overrides.#", "definednet_network.b", "config_overrides.#"),
		},
	}})
}
