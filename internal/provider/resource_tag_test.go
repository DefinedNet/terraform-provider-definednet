package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
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
    { key = "lighthouse.local_allow_list", value = jsonencode({ interfaces = { "docker.*" = false, "br-.*" = false } }) },
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
			config: `
resource "definednet_tag" "dup" {
  name = "env:dup"
  config_overrides = [
    { key = "logging.level", value = jsonencode("info") },
    { key = "logging.level", value = jsonencode("debug") },
  ]
}`,
			expectError: "Duplicate config override key",
		},
		{
			config: create,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_tag.prod", "id", "env:prod"),
				resource.TestCheckResourceAttr("definednet_tag.prod", "description", "production hosts"),
				resource.TestCheckResourceAttr("definednet_tag.prod", "config_overrides.#", "4"),
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

func TestTagResource_RemovedOutOfBand(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	runRemovedOutOfBandTest(t, f, `
resource "definednet_tag" "t" {
  name = "a:b"
}`, "definednet_tag.t", func() { clear(f.tags) })
}

func TestTagResource_PositionSentOnlyOnChange(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	cfg := func(description string) string {
		return fmt.Sprintf(`
resource "definednet_tag" "dev" {
  name = "env:dev"
}

resource "definednet_tag" "prod" {
  name        = "env:prod"
  description = %q
  before      = definednet_tag.dev.name
}
`, description)
	}
	lastPut := func(check func(client.TagUpdateRequest) error) resource.TestCheckFunc {
		return func(*terraform.State) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			req, ok := f.tagUpdates["env:prod"]
			if !ok {
				return fmt.Errorf("no PUT recorded for env:prod")
			}
			return check(req)
		}
	}

	runUnitTest(t, f, []testStep{
		{config: cfg("one")},
		{
			config: cfg("two"),
			checks: []resource.TestCheckFunc{
				lastPut(func(req client.TagUpdateRequest) error {
					if req.Before != nil || req.After != nil {
						return fmt.Errorf("unchanged position was re-sent: before=%v after=%v", req.Before, req.After)
					}
					return nil
				}),
				resource.TestCheckResourceAttr("definednet_tag.prod", "priority", "1"),
			},
		},
	})
}

func TestTagDataSource(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	cfg := `
resource "definednet_tag" "prod" {
  name        = "env:prod"
  description = "production hosts"
  config_overrides = [
    { key = "lighthouse.dns.port", value = jsonencode(53) },
  ]
  route_subscriptions = ["route-X47KHSCOSQJP5IOKNNKRRGHVAI"]
  firewall_rules = [
    { protocol = "ICMP" },
  ]
}

data "definednet_tag" "prod" {
  name = definednet_tag.prod.name
}
`
	runUnitTest(t, f, []testStep{
		{
			config: `
data "definednet_tag" "x" {
  name = "not a tag"
}`,
			expectError: "must be a key:value tag",
		},
		{
			config: `
data "definednet_tag" "x" {
  name = "env:missing"
}`,
			expectError: "Unable to read tag",
		},
		{
			config: cfg,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("data.definednet_tag.prod", "id", "env:prod"),
				resource.TestCheckResourceAttr("data.definednet_tag.prod", "description", "production hosts"),
				resource.TestCheckResourceAttrPair("data.definednet_tag.prod", "priority", "definednet_tag.prod", "priority"),
				resource.TestCheckResourceAttr("data.definednet_tag.prod", "config_overrides.#", "1"),
				resource.TestCheckResourceAttr("data.definednet_tag.prod", "config_overrides.0.value", "53"),
				resource.TestCheckResourceAttr("data.definednet_tag.prod", "route_subscriptions.#", "1"),
				resource.TestCheckResourceAttr("data.definednet_tag.prod", "firewall_rules.#", "1"),
			},
		},
	})
}
