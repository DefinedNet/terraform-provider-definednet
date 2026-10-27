package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

// The free plan allows two routes per org, so no test holds more than two.

func TestAccRouteResource(t *testing.T) {
	admin, name := accName(), accName()
	role := fmt.Sprintf(`
resource "definednet_role" "admin" {
  name = %q
}
`, admin)
	runAccTest(t, []testStep{
		{
			config: role + fmt.Sprintf(`
resource "definednet_route" "dc" {
  name           = %q
  description    = "on-prem subnets"
  routable_cidrs = {
    "192.168.14.0/24" = { install = true }
    "192.168.15.0/24" = {}
  }
  firewall_rules = [
    {
      local_cidr      = "192.168.14.56/32"
      protocol        = "TCP"
      description     = "ssh to bastion"
      allowed_role_id = definednet_role.admin.id
      port_range      = { from = 22, to = 22 }
    },
    {
      local_cidr = "ANY"
      protocol   = "ICMP"
    },
  ]
}
`, name),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrSet("definednet_route.dc", "id"),
				resource.TestCheckResourceAttr("definednet_route.dc", "routable_cidrs.%", "2"),
				resource.TestCheckResourceAttr("definednet_route.dc", "routable_cidrs.192.168.14.0/24.install", "true"),
				resource.TestCheckResourceAttr("definednet_route.dc", "routable_cidrs.192.168.15.0/24.install", "false"),
				resource.TestCheckResourceAttr("definednet_route.dc", "firewall_rules.#", "2"),
			},
		},
		{importState: true, importResource: "definednet_route.dc"},
		{
			config: role + fmt.Sprintf(`
resource "definednet_route" "dc" {
  name           = "%s-renamed"
  routable_cidrs = {
    "192.168.14.0/24" = { install = false }
  }
}
`, name),
			planChecks: expectUpdate("definednet_route.dc"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_route.dc", "name", name+"-renamed"),
				resource.TestCheckResourceAttr("definednet_route.dc", "description", ""),
				resource.TestCheckResourceAttr("definednet_route.dc", "routable_cidrs.%", "1"),
				resource.TestCheckResourceAttr("definednet_route.dc", "firewall_rules.#", "0"),
			},
		},
	})
}

func TestAccRouteResource_RemovedOutOfBand(t *testing.T) {
	runAccRemovedOutOfBandTest(t, fmt.Sprintf(`
resource "definednet_route" "r" {
  name = %q
}`, accName()), "definednet_route.r", func(c *client.Client, id string) error {
		return c.DeleteRoute(context.Background(), id)
	})
}

func TestAccRouteDataSource(t *testing.T) {
	dc, other := accName(), accName()
	runAccTest(t, []testStep{{
		config: fmt.Sprintf(`
resource "definednet_route" "dc" {
  name           = %q
  routable_cidrs = {
    "192.168.14.0/24" = { install = true }
  }
  firewall_rules = [
    { local_cidr = "ANY", protocol = "ICMP" },
  ]
}

resource "definednet_route" "other" {
  name = %q
}

data "definednet_route" "by_name" {
  name       = %q
  depends_on = [definednet_route.dc, definednet_route.other]
}

data "definednet_route" "by_id" {
  id = definednet_route.other.id
}
`, dc, other, dc),
		checks: []resource.TestCheckFunc{
			resource.TestCheckResourceAttrPair("data.definednet_route.by_name", "id", "definednet_route.dc", "id"),
			resource.TestCheckResourceAttr("data.definednet_route.by_name", "routable_cidrs.192.168.14.0/24.install", "true"),
			// Rules must come from the GET, not the summary list item.
			resource.TestCheckResourceAttr("data.definednet_route.by_name", "firewall_rules.#", "1"),
			resource.TestCheckResourceAttr("data.definednet_route.by_id", "name", other),
		},
	}})
}
