package provider

import (
	"context"
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

func TestAccTagResource(t *testing.T) {
	route, dev, prod := accName(), accTagName(), accTagName()
	base := fmt.Sprintf(`
resource "definednet_route" "office" {
  name           = %q
  routable_cidrs = { "10.10.0.0/16" = { install = true } }
}

resource "definednet_tag" "dev" {
  name = %q
}
`, route, dev)
	runAccTest(t, []testStep{
		{
			config: base + fmt.Sprintf(`
resource "definednet_tag" "prod" {
  name        = %q
  description = "production hosts"
  after       = definednet_tag.dev.name

  config_overrides = [
    { key = "lighthouse.dns.port", value = jsonencode(53) },
    { key = "definednet.dns.resolver_addrs", value = jsonencode(["10.0.0.53"]) },
    { key = "lighthouse.local_allow_list", value = jsonencode({ interfaces = { "docker.*" = false, "br-.*" = false } }) },
  ]

  route_subscriptions = [definednet_route.office.id]

  firewall_rules = [
    {
      protocol     = "TCP"
      description  = "metrics"
      allowed_tags = [definednet_tag.dev.name]
      port_range   = { from = 9100, to = 9100 }
    },
  ]
}
`, prod),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_tag.prod", "id", prod),
				resource.TestCheckResourceAttr("definednet_tag.prod", "config_overrides.#", "3"),
				resource.TestCheckResourceAttr("definednet_tag.prod", "route_subscriptions.#", "1"),
				resource.TestCheckResourceAttr("definednet_tag.prod", "firewall_rules.#", "1"),
				resource.TestCheckTypeSetElemAttrPair("definednet_tag.prod", "firewall_rules.*.allowed_tags.*", "definednet_tag.dev", "name"),
				expectPriorityAfter("definednet_tag.prod", "definednet_tag.dev"),
			},
		},
		// Several keys, one object-valued: import must match the config's
		// order and canonical JSON with no diff.
		{importState: true, importResource: "definednet_tag.prod", importVerifyIgnore: []string{"after"}},
		{
			config: base + fmt.Sprintf(`
resource "definednet_tag" "prod" {
  name  = %q
  after = definednet_tag.dev.name

  config_overrides = [
    { key = "lighthouse.dns.port", value = jsonencode(5353) },
  ]
}
`, prod),
			planChecks: expectUpdate("definednet_tag.prod"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_tag.prod", "description", ""),
				resource.TestCheckResourceAttr("definednet_tag.prod", "config_overrides.#", "1"),
				resource.TestCheckResourceAttr("definednet_tag.prod", "route_subscriptions.#", "0"),
				resource.TestCheckResourceAttr("definednet_tag.prod", "firewall_rules.#", "0"),
			},
		},
	})
}

// expectPriorityAfter checks that addr sits directly after prev. Absolute
// priorities depend on whatever else is in the org.
func expectPriorityAfter(addr, prev string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		res := s.RootModule().Resources
		a, _ := strconv.Atoi(res[addr].Primary.Attributes["priority"])
		b, _ := strconv.Atoi(res[prev].Primary.Attributes["priority"])
		if a != b+1 {
			return fmt.Errorf("%s priority %d, want %s's %d + 1", addr, a, prev, b)
		}
		return nil
	}
}

func TestAccTagResource_RemovedOutOfBand(t *testing.T) {
	runAccRemovedOutOfBandTest(t, fmt.Sprintf(`
resource "definednet_tag" "t" {
  name = %q
}`, accTagName()), "definednet_tag.t", func(c *client.Client, id string) error {
		return c.DeleteTag(context.Background(), id)
	})
}

func TestAccTagDataSource(t *testing.T) {
	route, prod := accName(), accTagName()
	runAccTest(t, []testStep{{
		config: fmt.Sprintf(`
resource "definednet_route" "r" {
  name = %q
}

resource "definednet_tag" "prod" {
  name        = %q
  description = "production hosts"
  config_overrides = [
    { key = "lighthouse.dns.port", value = jsonencode(53) },
  ]
  route_subscriptions = [definednet_route.r.id]
  firewall_rules = [
    { protocol = "ICMP" },
  ]
}

data "definednet_tag" "prod" {
  name = definednet_tag.prod.name
}
`, route, prod),
		checks: []resource.TestCheckFunc{
			resource.TestCheckResourceAttr("data.definednet_tag.prod", "id", prod),
			resource.TestCheckResourceAttr("data.definednet_tag.prod", "description", "production hosts"),
			resource.TestCheckResourceAttrPair("data.definednet_tag.prod", "priority", "definednet_tag.prod", "priority"),
			resource.TestCheckResourceAttr("data.definednet_tag.prod", "config_overrides.0.value", "53"),
			resource.TestCheckResourceAttr("data.definednet_tag.prod", "route_subscriptions.#", "1"),
			resource.TestCheckResourceAttr("data.definednet_tag.prod", "firewall_rules.#", "1"),
		},
	}})
}
