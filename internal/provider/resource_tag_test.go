package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestTagResource(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	create := `
resource "definednet_route" "office" {
  name           = "office"
  routable_cidrs = { "10.10.0.0/16" = { install = true } }
}

resource "definednet_tag" "dev" {
  name = "env:dev"
}

resource "definednet_tag" "prod" {
  name        = "env:prod"
  description = "production hosts"
  after       = definednet_tag.dev.name

  config_overrides = [
    { key = "lighthouse.dns.host", value = jsonencode("0.0.0.0") },
    { key = "lighthouse.dns.port", value = jsonencode(53) },
    { key = "definednet.dns.resolver_addrs", value = jsonencode(["10.0.0.53"]) },
  ]

  route_subscriptions = [definednet_route.office.id]

  firewall_rules = [
    {
      protocol     = "TCP"
      description  = "metrics"
      allowed_tags = ["role:monitoring"]
      port_range   = { from = 9100, to = 9100 }
    },
  ]
}
`
	update := `
resource "definednet_route" "office" {
  name           = "office"
  routable_cidrs = { "10.10.0.0/16" = { install = true } }
}

resource "definednet_tag" "dev" {
  name = "env:dev"
}

resource "definednet_tag" "prod" {
  name  = "env:prod"
  after = definednet_tag.dev.name

  config_overrides = [
    { key = "lighthouse.dns.port", value = jsonencode(5353) },
  ]
}
`
	runUnitTest(t, f, []testStep{
		{
			config: create,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_tag.prod", "id", "env:prod"),
				resource.TestCheckResourceAttr("definednet_tag.prod", "description", "production hosts"),
				resource.TestCheckResourceAttr("definednet_tag.prod", "config_overrides.#", "3"),
				resource.TestCheckTypeSetElemNestedAttrs("definednet_tag.prod", "config_overrides.*", map[string]string{
					"key": "lighthouse.dns.host", "value": `"0.0.0.0"`,
				}),
				resource.TestCheckTypeSetElemNestedAttrs("definednet_tag.prod", "config_overrides.*", map[string]string{
					"key": "lighthouse.dns.port", "value": "53",
				}),
				resource.TestCheckTypeSetElemNestedAttrs("definednet_tag.prod", "config_overrides.*", map[string]string{
					"key": "definednet.dns.resolver_addrs", "value": `["10.0.0.53"]`,
				}),
				resource.TestCheckResourceAttr("definednet_tag.prod", "route_subscriptions.#", "1"),
				resource.TestCheckResourceAttr("definednet_tag.prod", "firewall_rules.#", "1"),
				resource.TestCheckTypeSetElemNestedAttrs("definednet_tag.prod", "firewall_rules.*", map[string]string{
					"protocol": "TCP", "allowed_tags.#": "1", "port_range.from": "9100",
				}),
				resource.TestCheckTypeSetElemAttr("definednet_tag.prod", "firewall_rules.*.allowed_tags.*", "role:monitoring"),
				// dev was created first (priority 1); prod placed after it takes 2.
				resource.TestCheckResourceAttr("definednet_tag.dev", "priority", "1"),
				resource.TestCheckResourceAttr("definednet_tag.prod", "priority", "2"),
				resource.TestCheckResourceAttr("definednet_tag.dev", "route_subscriptions.#", "0"),
				resource.TestCheckResourceAttr("definednet_tag.dev", "config_overrides.#", "0"),
			},
		},
		{importState: true, importResource: "definednet_tag.prod", importVerifyIgnore: []string{"after"}},
		{
			config: update,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_tag.prod", "description", ""),
				resource.TestCheckResourceAttr("definednet_tag.prod", "config_overrides.#", "1"),
				resource.TestCheckTypeSetElemNestedAttrs("definednet_tag.prod", "config_overrides.*", map[string]string{
					"key": "lighthouse.dns.port", "value": "5353",
				}),
				resource.TestCheckResourceAttr("definednet_tag.prod", "route_subscriptions.#", "0"),
				resource.TestCheckResourceAttr("definednet_tag.prod", "firewall_rules.#", "0"),
			},
		},
	})
}

func TestTagResource_Validation(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	runUnitTest(t, f, []testStep{
		{
			config: `
resource "definednet_tag" "t" {
  name = "novalue"
}`,
			expectError: "key:value",
		},
		{
			config: `
resource "definednet_tag" "t" {
  name   = "a:b"
  before = "x:y"
  after  = "y:z"
}`,
			expectError: "Invalid Attribute Combination",
		},
		{
			config: `
resource "definednet_tag" "t" {
  name             = "a:b"
  config_overrides = [{ key = "k", value = "not json" }]
}`,
			expectError: "(?s)Invalid JSON String Value",
		},
	})
}
