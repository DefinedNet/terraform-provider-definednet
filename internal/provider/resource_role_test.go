package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestRoleResource(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	// Rules are deliberately listed in the reverse of the API's sort order
	// (by from-port) to exercise order matching.
	create := `
resource "definednet_role" "admin" {
  name = "admin"
}

resource "definednet_role" "web" {
  name        = "web"
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
      allowed_tags    = ["env:prod", "team:ops"]
      port_range      = { from = 22, to = 22 }
    },
    {
      protocol = "ICMP"
    },
  ]
}
`
	update := `
resource "definednet_role" "admin" {
  name = "admin"
}

resource "definednet_role" "web" {
  name = "web"
  firewall_rules = [
    {
      protocol   = "TCP"
      port_range = { from = 80, to = 443 }
    },
  ]
}
`
	runUnitTest(t, f, []testStep{
		{
			config: create,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrSet("definednet_role.web", "id"),
				resource.TestCheckResourceAttr("definednet_role.web", "description", "web servers"),
				resource.TestCheckResourceAttr("definednet_role.web", "firewall_rules.#", "3"),
				resource.TestCheckTypeSetElemNestedAttrs("definednet_role.web", "firewall_rules.*", map[string]string{
					"protocol":        "TCP",
					"description":     "https",
					"port_range.from": "443",
					"port_range.to":   "443",
				}),
				resource.TestCheckTypeSetElemNestedAttrs("definednet_role.web", "firewall_rules.*", map[string]string{
					"protocol":        "TCP",
					"description":     "ssh from admins",
					"allowed_tags.#":  "2",
					"port_range.from": "22",
				}),
				resource.TestCheckTypeSetElemNestedAttrs("definednet_role.web", "firewall_rules.*", map[string]string{
					"protocol":    "ICMP",
					"description": "",
				}),
				resource.TestCheckResourceAttr("definednet_role.admin", "firewall_rules.#", "0"),
				resource.TestCheckResourceAttr("definednet_role.admin", "description", ""),
			},
		},
		{importState: true, importResource: "definednet_role.web"},
		{
			config: update,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_role.web", "description", ""),
				resource.TestCheckResourceAttr("definednet_role.web", "firewall_rules.#", "1"),
				resource.TestCheckTypeSetElemNestedAttrs("definednet_role.web", "firewall_rules.*", map[string]string{
					"protocol":        "TCP",
					"port_range.from": "80",
					"port_range.to":   "443",
				}),
			},
		},
	})
}

func TestRoleResource_RenameReplaces(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	runUnitTest(t, f, []testStep{
		{config: `
resource "definednet_role" "r" {
  name = "one"
}`},
		{
			config: `
resource "definednet_role" "r" {
  name = "two"
}`,
			planChecks: expectReplace("definednet_role.r"),
			checks:     []resource.TestCheckFunc{resource.TestCheckResourceAttr("definednet_role.r", "name", "two")},
		},
	})
}

func TestRoleResource_EmptyAllowedTagsRejected(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	runUnitTest(t, f, []testStep{{
		config: `
resource "definednet_role" "r" {
  name = "r"
  firewall_rules = [{ protocol = "ANY", allowed_tags = [] }]
}`,
		expectError: "at least 1",
	}})
}

func TestRoleResource_RemovedOutOfBand(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	runRemovedOutOfBandTest(t, f, `
resource "definednet_role" "r" {
  name = "r"
}`, "definednet_role.r", func() { clear(f.roles) })
}

func TestRoleDataSource(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	cfg := `
resource "definednet_role" "web" {
  name = "web"
  firewall_rules = [
    { protocol = "TCP", port_range = { from = 443, to = 443 } },
  ]
}

resource "definednet_role" "other" {
  name = "other"
}

data "definednet_role" "by_name" {
  name       = "web"
  depends_on = [definednet_role.web, definednet_role.other]
}

data "definednet_role" "by_id" {
  id = definednet_role.other.id
}
`
	runUnitTest(t, f, []testStep{
		{
			config:      `data "definednet_role" "x" {}`,
			expectError: "Exactly one of these attributes must be configured",
		},
		{
			config: `
data "definednet_role" "x" {
  name = "missing"
}`,
			expectError: "Role not found",
		},
		{
			config: cfg,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrPair("data.definednet_role.by_name", "id", "definednet_role.web", "id"),
				// Rules must come from the GET, not the summary list item.
				resource.TestCheckResourceAttr("data.definednet_role.by_name", "firewall_rules.#", "1"),
				resource.TestCheckResourceAttr("data.definednet_role.by_name", "firewall_rules.0.port_range.from", "443"),
				resource.TestCheckResourceAttr("data.definednet_role.by_id", "name", "other"),
				resource.TestCheckResourceAttr("data.definednet_role.by_id", "firewall_rules.#", "0"),
			},
		},
	})
}
