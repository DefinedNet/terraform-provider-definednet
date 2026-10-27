package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
)

func TestAccRoleResource(t *testing.T) {
	admin, web, tag := accName(), accName(), accTagName()
	base := fmt.Sprintf(`
resource "definednet_role" "admin" {
  name = %q
}

resource "definednet_tag" "ops" {
  name = %q
}
`, admin, tag)
	runAccTest(t, []testStep{
		{
			config: base + fmt.Sprintf(`
resource "definednet_role" "web" {
  name        = %q
  description = "web servers"
  firewall_rules = [
    {
      protocol    = "TCP"
      description = "https"
      port_range  = { from = 443, to = 443 }
    },
    {
      protocol        = "TCP"
      description     = "ssh from admins"
      allowed_role_id = definednet_role.admin.id
      allowed_tags    = [definednet_tag.ops.name]
      port_range      = { from = 22, to = 22 }
    },
    {
      protocol = "ICMP"
    },
  ]
}
`, web),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrSet("definednet_role.web", "id"),
				resource.TestCheckResourceAttr("definednet_role.web", "firewall_rules.#", "3"),
				resource.TestCheckTypeSetElemNestedAttrs("definednet_role.web", "firewall_rules.*", map[string]string{
					"protocol": "TCP", "description": "ssh from admins", "allowed_tags.#": "1", "port_range.from": "22",
				}),
				resource.TestCheckTypeSetElemAttrPair("definednet_role.web", "firewall_rules.*.allowed_role_id", "definednet_role.admin", "id"),
				resource.TestCheckResourceAttr("definednet_role.admin", "firewall_rules.#", "0"),
			},
		},
		{importState: true, importResource: "definednet_role.web"},
		{
			config: base + fmt.Sprintf(`
resource "definednet_role" "web" {
  name = %q
  firewall_rules = [
    { protocol = "TCP", port_range = { from = 80, to = 443 } },
  ]
}
`, web),
			planChecks: expectUpdate("definednet_role.web"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_role.web", "description", ""),
				resource.TestCheckResourceAttr("definednet_role.web", "firewall_rules.#", "1"),
			},
		},
	})
}

// A role whose rule allows its own role is created with two requests, the
// second filling in the new ID.
func TestAccRoleResource_SelfRule(t *testing.T) {
	admin, mesh := accName(), accName()
	cfg := func(description string) string {
		return fmt.Sprintf(`
resource "definednet_role" "admin" {
  name = %q
}

resource "definednet_role" "mesh" {
  name        = %q
  description = %q
  firewall_rules = [
    {
      protocol        = "ANY"
      description     = "peers"
      allowed_role_id = "self"
    },
    {
      protocol        = "TCP"
      allowed_role_id = definednet_role.admin.id
      port_range      = { from = 22, to = 22 }
    },
  ]
}
`, admin, mesh, description)
	}
	selfRule := resource.TestCheckTypeSetElemNestedAttrs("definednet_role.mesh", "firewall_rules.*", map[string]string{
		"protocol": "ANY", "description": "peers", "allowed_role_id": "self",
	})
	runAccTest(t, []testStep{
		{
			config: cfg(""),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_role.mesh", "firewall_rules.#", "2"),
				selfRule,
				resource.TestCheckTypeSetElemAttrPair("definednet_role.mesh", "firewall_rules.*.allowed_role_id", "definednet_role.admin", "id"),
			},
		},
		{importState: true, importResource: "definednet_role.mesh"},
		{
			config:     cfg("mesh peers"),
			planChecks: expectUpdate("definednet_role.mesh"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_role.mesh", "description", "mesh peers"),
				selfRule,
			},
		},
	})
}

func TestAccRoleResource_RemovedOutOfBand(t *testing.T) {
	runAccRemovedOutOfBandTest(t, fmt.Sprintf(`
resource "definednet_role" "r" {
  name = %q
}`, accName()), "definednet_role.r", func(c *client.Client, id string) error {
		return c.DeleteRole(context.Background(), id)
	})
}

func TestAccRoleDataSource(t *testing.T) {
	web, other := accName(), accName()
	runAccTest(t, []testStep{{
		config: fmt.Sprintf(`
resource "definednet_role" "web" {
  name = %q
  firewall_rules = [
    { protocol = "TCP", port_range = { from = 443, to = 443 } },
  ]
}

resource "definednet_role" "other" {
  name = %q
}

data "definednet_role" "by_name" {
  name       = %q
  depends_on = [definednet_role.web, definednet_role.other]
}

data "definednet_role" "by_id" {
  id = definednet_role.other.id
}
`, web, other, web),
		checks: []resource.TestCheckFunc{
			resource.TestCheckResourceAttrPair("data.definednet_role.by_name", "id", "definednet_role.web", "id"),
			// Rules must come from the GET, not the summary list item.
			resource.TestCheckResourceAttr("data.definednet_role.by_name", "firewall_rules.#", "1"),
			resource.TestCheckResourceAttr("data.definednet_role.by_id", "name", other),
		},
	}})
}
