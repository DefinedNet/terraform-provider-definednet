package provider

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/johnmaguire/terraform-provider-definednet/internal/client"
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

// expectRolePuts checks how many times roles were PUT across every role the
// fake has seen.
func expectRolePuts(f *fakeAPI, want int) resource.TestCheckFunc {
	return func(*terraform.State) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		got := 0
		for _, n := range f.rolePuts {
			got += n
		}
		if got != want {
			return fmt.Errorf("roles PUT %d times, want %d", got, want)
		}
		return nil
	}
}

func TestRoleResource_SelfRule(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	create := `
resource "definednet_role" "admin" {
  name = "admin"
}

resource "definednet_role" "mesh" {
  name = "mesh"
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
`
	update := `
resource "definednet_role" "admin" {
  name = "admin"
}

resource "definednet_role" "mesh" {
  name        = "mesh"
  description = "mesh peers"
  firewall_rules = [
    {
      protocol        = "ANY"
      description     = "peers"
      allowed_role_id = "self"
    },
  ]
}
`
	selfRule := resource.TestCheckTypeSetElemNestedAttrs("definednet_role.mesh", "firewall_rules.*", map[string]string{
		"protocol":        "ANY",
		"description":     "peers",
		"allowed_role_id": "self",
	})
	runUnitTest(t, f, []testStep{
		{
			config: create,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_role.mesh", "firewall_rules.#", "2"),
				selfRule,
				resource.TestCheckTypeSetElemAttrPair("definednet_role.mesh", "firewall_rules.*.allowed_role_id", "definednet_role.admin", "id"),
				// Only the role with a self rule needs the follow-up PUT.
				expectRolePuts(f, 1),
			},
		},
		{importState: true, importResource: "definednet_role.mesh"},
		{
			config: update,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_role.mesh", "description", "mesh peers"),
				resource.TestCheckResourceAttr("definednet_role.mesh", "firewall_rules.#", "1"),
				selfRule,
				expectRolePuts(f, 2),
			},
		},
	})
}

func TestRoleResource_SelfRejectedElsewhere(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	runUnitTest(t, f, []testStep{
		{
			config: `
resource "definednet_tag" "t" {
  name           = "env:dev"
  firewall_rules = [{ protocol = "ANY", allowed_role_id = "self" }]
}`,
			expectError: `"self" is only valid in a definednet_role`,
		},
		{
			config: `
resource "definednet_route" "r" {
  name           = "r"
  routable_cidrs = { "10.10.0.0/16" = {} }
  firewall_rules = [{ local_cidr = "ANY", protocol = "ANY", allowed_role_id = "self" }]
}`,
			expectError: `"self" is only valid in a definednet_role`,
		},
	})
}

func TestMarkSelfRules(t *testing.T) {
	ctx := context.Background()
	id := "role-OWN"
	api, diags := flattenFirewallRules(ctx, []client.FirewallRule{{Protocol: "ANY", AllowedRoleID: &id}}, false)
	if diags.HasError() {
		t.Fatal(diags)
	}
	want := types.StringValue(selfRoleID)
	if v := markSelfRules(ctx, api, id).Elements()[0].(types.Object).Attributes()["allowed_role_id"]; !v.Equal(want) {
		t.Errorf("allowed_role_id = %v, want %v", v, want)
	}
}

// A config that spells the role's own ID literally is rejected at plan time.
// Import is used because the ID must exist before a config can name it.
func TestRoleResource_LiteralOwnIDRejected(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	id := "role-FIXED"
	f.roles[id] = &client.Role{ID: id, Name: "mesh", FirewallRules: []client.FirewallRule{{Protocol: "ANY", AllowedRoleID: &id}}}

	cfg := func(ref string) string {
		return fmt.Sprintf(`
import {
  to = definednet_role.mesh
  id = "role-FIXED"
}

resource "definednet_role" "mesh" {
  name           = "mesh"
  firewall_rules = [{ protocol = "ANY", allowed_role_id = %q }]
}`, ref)
	}
	runUnitTest(t, f, []testStep{
		{config: cfg(id), expectError: `"role-FIXED" is this role's own ID; write "self" instead`},
		{config: cfg(selfRoleID), planChecks: []plancheck.PlanCheck{plancheck.ExpectResourceAction("definednet_role.mesh", plancheck.ResourceActionNoop)}},
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
