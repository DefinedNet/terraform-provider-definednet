package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestRouteResource(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	create := `
resource "definednet_role" "admin" {
  name = "admin"
}

resource "definednet_route" "dc" {
  name           = "datacenter"
  description    = "on-prem subnets"
  router_host_id = "host-24NVITKMNU3CYCEDNFWKAOBX7I"
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
`
	update := `
resource "definednet_role" "admin" {
  name = "admin"
}

resource "definednet_route" "dc" {
  name           = "datacenter-renamed"
  routable_cidrs = {
    "192.168.14.0/24" = { install = false }
  }
}
`
	runUnitTest(t, f, []testStep{
		{
			config: create,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrSet("definednet_route.dc", "id"),
				resource.TestCheckResourceAttr("definednet_route.dc", "router_host_id", "host-24NVITKMNU3CYCEDNFWKAOBX7I"),
				resource.TestCheckResourceAttr("definednet_route.dc", "routable_cidrs.%", "2"),
				resource.TestCheckResourceAttr("definednet_route.dc", "routable_cidrs.192.168.14.0/24.install", "true"),
				resource.TestCheckResourceAttr("definednet_route.dc", "routable_cidrs.192.168.15.0/24.install", "false"),
				resource.TestCheckResourceAttr("definednet_route.dc", "firewall_rules.#", "2"),
				resource.TestCheckTypeSetElemNestedAttrs("definednet_route.dc", "firewall_rules.*", map[string]string{
					"local_cidr": "192.168.14.56/32", "protocol": "TCP", "port_range.from": "22",
				}),
				resource.TestCheckTypeSetElemNestedAttrs("definednet_route.dc", "firewall_rules.*", map[string]string{
					"local_cidr": "ANY", "protocol": "ICMP", "description": "",
				}),
			},
		},
		{importState: true, importResource: "definednet_route.dc"},
		{
			config:     update,
			planChecks: expectUpdate("definednet_route.dc"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_route.dc", "name", "datacenter-renamed"),
				resource.TestCheckResourceAttr("definednet_route.dc", "description", ""),
				resource.TestCheckNoResourceAttr("definednet_route.dc", "router_host_id"),
				resource.TestCheckResourceAttr("definednet_route.dc", "routable_cidrs.%", "1"),
				resource.TestCheckResourceAttr("definednet_route.dc", "firewall_rules.#", "0"),
			},
		},
	})
}

func TestRouteResource_Validation(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	runUnitTest(t, f, []testStep{
		{
			config: `
resource "definednet_route" "r" {
  name           = "r"
  routable_cidrs = { "not-a-cidr" = {} }
}`,
			expectError: "IPv4 network",
		},
		{
			config: `
resource "definednet_route" "r" {
  name           = "r"
  routable_cidrs = { "192.168.14.1/24" = {} }
}`,
			expectError: "no host bits set",
		},
		{
			config: `
resource "definednet_route" "r" {
  name           = "r"
  firewall_rules = [{ local_cidr = "any", protocol = "ANY" }]
}`,
			expectError: "must be ANY or an IPv4 network",
		},
		{
			config: `
resource "definednet_route" "r" {
  name           = "r"
  routable_cidrs = { "192.168.14.0/24" = {} }
  firewall_rules = [{ local_cidr = "192.168.15.0/24", protocol = "ANY" }]
}`,
			expectError: "must overlap one of routable_cidrs",
		},
		{
			config: `
resource "definednet_route" "r" {
  name           = "r"
  routable_cidrs = { "192.168.14.0/24" = {} }
  firewall_rules = [{ local_cidr = "ANY", protocol = "TCP", port_range = { from = 443, to = 80 } }]
}`,
			expectError: "Invalid port range",
		},
	})
}

func TestRouteResource_RemovedOutOfBand(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	runRemovedOutOfBandTest(t, f, `
resource "definednet_route" "r" {
  name = "r"
}`, "definednet_route.r", func() { clear(f.routes) })
}
