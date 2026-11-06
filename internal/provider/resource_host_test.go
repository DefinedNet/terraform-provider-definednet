package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

const hostBase = `
resource "definednet_network" "n" {
  name      = "n"
  ipv4_cidr = "10.10.0.0/16"
}

resource "definednet_role" "r" {
  name = "r"
}
`

func onlyHost(f *fakeAPI) *client.Host {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, h := range f.hosts {
		return h
	}
	return nil
}

func TestHostResource(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	lighthouse := hostBase + `
resource "definednet_host" "lh" {
  network_id       = definednet_network.n.id
  name             = "lighthouse-1"
  role_id          = definednet_role.r.id
  is_lighthouse    = true
  ipv4_address     = "10.10.0.10"
  static_addresses = ["203.0.113.10:4242", "lh1.example.com:4242"]
  listen_port      = 4242
  tags             = ["env:prod", "site:ams"]
  config_overrides = [
    { key = "lighthouse.serve_dns", value = jsonencode(true) },
    { key = "tun.unsafe_routes", value = jsonencode([{ route = "192.168.0.0/24", via = "10.10.0.10" }]) },
  ]
}
`
	updated := hostBase + `
resource "definednet_host" "lh" {
  network_id       = definednet_network.n.id
  name             = "lighthouse-renamed"
  is_lighthouse    = true
  ipv4_address     = "10.10.0.10"
  static_addresses = ["203.0.113.11:4243"]
  listen_port      = 4243
}
`
	runUnitTest(t, f, []testStep{
		{
			config: lighthouse,
			checks: []resource.TestCheckFunc{
				resource.TestMatchResourceAttr("definednet_host.lh", "id", regexp.MustCompile(`^host-`)),
				resource.TestCheckResourceAttr("definednet_host.lh", "ipv4_address", "10.10.0.10"),
				resource.TestCheckResourceAttr("definednet_host.lh", "ip_addresses.#", "2"),
				resource.TestCheckResourceAttr("definednet_host.lh", "ip_addresses.0", "10.10.0.10"),
				resource.TestCheckResourceAttr("definednet_host.lh", "is_blocked", "false"),
				resource.TestCheckResourceAttrSet("definednet_host.lh", "enrollment_code"),
				resource.TestCheckNoResourceAttr("definednet_host.lh", "enrollment_code_lifetime_seconds"),
				resource.TestCheckResourceAttr("definednet_host.lh", "static_addresses.#", "2"),
				resource.TestCheckResourceAttr("definednet_host.lh", "tags.#", "2"),
				resource.TestCheckResourceAttr("definednet_host.lh", "config_overrides.#", "2"),
				resource.TestCheckResourceAttrPair("definednet_host.lh", "role_id", "definednet_role.r", "id"),
			},
		},
		// GET never returns the code.
		{importState: true, importResource: "definednet_host.lh", importVerifyIgnore: []string{"enrollment_code"}},
		{
			config:     updated,
			planChecks: expectUpdate("definednet_host.lh"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_host.lh", "name", "lighthouse-renamed"),
				resource.TestCheckNoResourceAttr("definednet_host.lh", "role_id"),
				resource.TestCheckResourceAttr("definednet_host.lh", "tags.#", "0"),
				resource.TestCheckResourceAttr("definednet_host.lh", "config_overrides.#", "0"),
				resource.TestCheckResourceAttr("definednet_host.lh", "listen_port", "4243"),
				resource.TestCheckResourceAttr("definednet_host.lh", "ipv4_address", "10.10.0.10"),
			},
		},
		{
			// Addresses cannot change in place.
			config:     strings.Replace(updated, `"10.10.0.10"`, `"10.10.0.11"`, 1),
			planChecks: expectReplace("definednet_host.lh"),
			checks:     []resource.TestCheckFunc{resource.TestCheckResourceAttr("definednet_host.lh", "ipv4_address", "10.10.0.11")},
		},
		{
			config:     strings.Replace(strings.Replace(updated, `"10.10.0.10"`, `"10.10.0.11"`, 1), "is_lighthouse", "is_relay", 1),
			planChecks: expectReplace("definednet_host.lh"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_host.lh", "is_lighthouse", "false"),
				resource.TestCheckResourceAttr("definednet_host.lh", "is_relay", "true"),
			},
		},
	})
}

// Without ipv4_address the provider asks for an address from the network's
// IPv4 prefix, and a host on an IPv6-only network gets none.
func TestHostResource_AssignedAddresses(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	cfg := hostBase + `
resource "definednet_network" "v6" {
  name = "v6"
}

resource "definednet_host" "a" {
  network_id = definednet_network.n.id
  name       = "a"
}

resource "definednet_host" "b" {
  network_id = definednet_network.v6.id
  name       = "b"
}
`
	runUnitTest(t, f, []testStep{
		{
			config: cfg,
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_host.a", "ipv4_address", "10.10.0.1"),
				resource.TestCheckResourceAttr("definednet_host.a", "ip_addresses.#", "2"),
				resource.TestCheckResourceAttr("definednet_host.a", "listen_port", "0"),
				resource.TestCheckNoResourceAttr("definednet_host.b", "ipv4_address"),
				resource.TestCheckResourceAttr("definednet_host.b", "ip_addresses.#", "1"),
			},
		},
		{
			// Renaming keeps the assigned address rather than planning a replacement.
			config:     strings.Replace(cfg, `name       = "a"`, `name       = "a2"`, 1),
			planChecks: expectUpdate("definednet_host.a"),
			checks:     []resource.TestCheckFunc{resource.TestCheckResourceAttr("definednet_host.a", "ipv4_address", "10.10.0.1")},
		},
	})
}

// A host created before its network had an IPv4 prefix gets an address in
// place; only changing an existing address replaces the host.
func TestHostResource_AddIPv4(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	cfg := func(cidr, addr string) string {
		return fmt.Sprintf(`
resource "definednet_network" "n" {
  name = "n"
  %s
}

resource "definednet_host" "h" {
  network_id = definednet_network.n.id
  name       = "h"
  %s
}
`, cidr, addr)
	}
	const cidr = `ipv4_cidr = "10.30.0.0/16"`
	noop := []plancheck.PlanCheck{plancheck.ExpectResourceAction("definednet_host.h", plancheck.ResourceActionNoop)}
	runUnitTest(t, f, []testStep{
		{
			config: cfg("", ""),
			checks: []resource.TestCheckFunc{
				resource.TestCheckNoResourceAttr("definednet_host.h", "ipv4_address"),
				resource.TestCheckResourceAttr("definednet_host.h", "ip_addresses.#", "1"),
			},
		},
		{
			// A rejected address must not be recorded as assigned.
			config:      cfg("", `ipv4_address = "10.30.0.5"`),
			expectError: "network does not have an IPv4 prefix",
		},
		{
			// Omitted, the address is not assigned on update.
			config:     cfg(cidr, ""),
			planChecks: noop,
			checks:     []resource.TestCheckFunc{resource.TestCheckNoResourceAttr("definednet_host.h", "ipv4_address")},
		},
		{
			config:     cfg(cidr, `ipv4_address = "10.30.0.5"`),
			planChecks: expectUpdate("definednet_host.h"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_host.h", "ipv4_address", "10.30.0.5"),
				resource.TestCheckResourceAttr("definednet_host.h", "ip_addresses.#", "2"),
				resource.TestCheckResourceAttr("definednet_host.h", "ip_addresses.0", "10.30.0.5"),
			},
		},
		{
			config:     cfg(cidr, ""),
			planChecks: noop,
			checks:     []resource.TestCheckFunc{resource.TestCheckResourceAttr("definednet_host.h", "ipv4_address", "10.30.0.5")},
		},
		{
			config:     cfg(cidr, `ipv4_address = "10.30.0.6"`),
			planChecks: expectReplace("definednet_host.h"),
			checks:     []resource.TestCheckFunc{resource.TestCheckResourceAttr("definednet_host.h", "ipv4_address", "10.30.0.6")},
		},
	})
}

// An address the add-IP route committed stays in state when the PUT that
// follows fails, so a retry without refresh does not add it again.
func TestHostResource_AddIPv4ThenPutFails(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	cfg := func(cidr, name, addr string) string {
		return fmt.Sprintf(`
resource "definednet_network" "n" {
  name = "n"
  %s
}

resource "definednet_host" "other" {
  network_id = definednet_network.n.id
  name       = "taken"
}

resource "definednet_host" "h" {
  network_id = definednet_network.n.id
  name       = %q
  %s
}
`, cidr, name, addr)
	}
	const cidr = `ipv4_cidr = "10.30.0.0/16"`
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: testProviderFactories,
		AdditionalCLIOptions:     &resource.AdditionalCLIOptions{Plan: resource.PlanOptions{NoRefresh: true}},
		Steps: buildSteps(providerConfig(f), []testStep{
			{config: cfg("", "h", "")},
			{
				config:      cfg(cidr, "taken", `ipv4_address = "10.30.0.5"`),
				expectError: "ERR_DUPLICATE_VALUE",
			},
			{
				config:     cfg(cidr, "h", `ipv4_address = "10.30.0.5"`),
				planChecks: []plancheck.PlanCheck{plancheck.ExpectResourceAction("definednet_host.h", plancheck.ResourceActionNoop)},
				checks:     []resource.TestCheckFunc{resource.TestCheckResourceAttr("definednet_host.h", "ipv4_address", "10.30.0.5")},
			},
		}),
	})
}

// Tags and static addresses changed outside Terraform show as drift and are put back.
func TestHostResource_Drift(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	cfg := hostBase + `
resource "definednet_host" "h" {
  network_id       = definednet_network.n.id
  name             = "h"
  tags             = ["env:prod"]
  static_addresses = ["203.0.113.10:4242"]
}
`
	runUnitTest(t, f, []testStep{
		{config: cfg},
		{
			preConfig: func() {
				h := onlyHost(f)
				h.Tags = []string{"env:dev"}
				h.StaticAddresses = nil
			},
			config:     cfg,
			planChecks: expectUpdate("definednet_host.h"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckTypeSetElemAttr("definednet_host.h", "tags.*", "env:prod"),
				resource.TestCheckResourceAttr("definednet_host.h", "static_addresses.#", "1"),
			},
		},
	})
}

func TestHostResource_Validation(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	for _, tc := range []struct{ body, want string }{
		{`name = "lh"
is_lighthouse = true
listen_port = 4242`, "Lighthouses need at least one static address"},
		{`name = "lh"
is_lighthouse = true
static_addresses = ["203.0.113.1:4242"]`, "Lighthouses and relays need a non-zero listen_port"},
		{`name = "r"
is_relay = true`, "Lighthouses and relays need a non-zero listen_port"},
		{`name = "x"
is_lighthouse = true
is_relay = true
listen_port = 1
static_addresses = ["203.0.113.1:4242"]`, "A lighthouse cannot also be a relay"},
		{`name = "ANY"`, "value must be none of"},
		{`name = "x"
ipv4_address = "10.10.0.0/24"`, "must be an IPv4 address"},
		{`name = "x"
ipv4_address = "10.10.0.05"`, "must be an IPv4 address"},
		{`name = "x"
listen_port = 70000`, "value must be between 0 and 65535"},
		{`name = "x"
tags = ["nocolon"]`, "must be a key:value tag"},
	} {
		runUnitTest(t, f, []testStep{{
			config:      "resource \"definednet_host\" \"h\" {\nnetwork_id = \"network-X\"\n" + tc.body + "\n}",
			expectError: tc.want,
		}})
	}
}

func TestHostResource_APIErrors(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	runUnitTest(t, f, []testStep{
		{
			config: hostBase + `
resource "definednet_host" "a" {
  network_id = definednet_network.n.id
  name       = "dup"
}

resource "definednet_host" "b" {
  network_id = definednet_network.n.id
  name       = "dup"
  depends_on = [definednet_host.a]
}`,
			expectError: "bring it under management with terraform import",
		},
		{
			config: hostBase + `
resource "definednet_host" "h" {
  network_id   = definednet_network.n.id
  name         = "h"
  ipv4_address = "10.99.0.1"
}`,
			expectError: "ERR_OUT_OF_RANGE",
		},
		{
			// The network and broadcast addresses are inside the prefix but not assignable.
			config: hostBase + `
resource "definednet_host" "h" {
  network_id   = definednet_network.n.id
  name         = "h"
  ipv4_address = "10.10.0.0"
}`,
			expectError: "ERR_OUT_OF_RANGE",
		},
		{
			config: hostBase + `
resource "definednet_host" "h" {
  network_id   = definednet_network.n.id
  name         = "h"
  ipv4_address = "10.10.255.255"
}`,
			expectError: "ERR_OUT_OF_RANGE",
		},
	})
}

func TestHostResource_RemovedOutOfBand(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	runRemovedOutOfBandTest(t, f, hostBase+`
resource "definednet_host" "h" {
  network_id = definednet_network.n.id
  name       = "h"
}`, "definednet_host.h", func() { clear(f.hosts) })
}

// The code is minted at create and again only when the triggers change; a
// failed mint keeps the previous code so the trigger change stays pending.
func TestHostResource_EnrollmentCode(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	cfg := func(triggers, lifetime string) string {
		return hostBase + fmt.Sprintf(`
resource "definednet_host" "h" {
  network_id               = definednet_network.n.id
  name                     = "pet"
  enrollment_code_triggers = %s
  %s
}
`, triggers, lifetime)
	}
	codes := func() []client.EnrollmentCode {
		id := onlyHost(f).ID
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.enrollmentCodes[id]
	}
	var seen []string
	codeIs := func(n int) resource.TestCheckFunc {
		return resource.TestCheckResourceAttrWith("definednet_host.h", "enrollment_code", func(v string) error {
			minted := codes()
			if len(minted) != n || minted[n-1].Code != v {
				return fmt.Errorf("state code %q, fake minted %d codes %v, want %d with the last in state", v, len(minted), minted, n)
			}
			seen = append(seen, v)
			return nil
		})
	}
	setBlocked := func(b bool) func() {
		return func() {
			h := onlyHost(f)
			f.mu.Lock()
			defer f.mu.Unlock()
			h.IsBlocked = b
		}
	}
	unknownCode := plancheck.ExpectUnknownValue("definednet_host.h", tfjsonpath.New("enrollment_code"))
	// Enrollment-only applies must not touch the PUT route.
	putsAre := func(n int) resource.TestCheckFunc {
		return func(*terraform.State) error {
			id := onlyHost(f).ID
			f.mu.Lock()
			defer f.mu.Unlock()
			if f.hostPuts[id] != n {
				return fmt.Errorf("host PUTs: got %d, want %d", f.hostPuts[id], n)
			}
			return nil
		}
	}

	runUnitTest(t, f, []testStep{
		{
			// Unknown triggers are fine at create: the code is minted either way.
			config: cfg(`{ role = definednet_role.r.id }`, ""),
			checks: []resource.TestCheckFunc{codeIs(1), resource.TestCheckNoResourceAttr("definednet_host.h", "enrollment_code_lifetime_seconds")},
		},
		{
			// A value unknown at plan could resolve equal during apply and skip
			// the mint after the dependent machine is gone, so the plan refuses it.
			config:      cfg(`{ role = definednet_role.r2.id }`, "") + `resource "definednet_role" "r2" { name = "r2" }`,
			expectError: "must be known at plan time",
		},
		{
			config:     cfg(`{ ami = "ami-1" }`, ""),
			planChecks: append(expectUpdate("definednet_host.h"), unknownCode),
			checks:     []resource.TestCheckFunc{codeIs(2)},
		},
		{
			// A lifetime change alone is an update without a mint.
			config:     cfg(`{ ami = "ami-1" }`, "enrollment_code_lifetime_seconds = 3600"),
			planChecks: append(expectUpdate("definednet_host.h"), plancheck.ExpectKnownValue("definednet_host.h", tfjsonpath.New("enrollment_code"), knownvalue.NotNull())),
			checks:     []resource.TestCheckFunc{codeIs(2), putsAre(0), resource.TestCheckResourceAttr("definednet_host.h", "enrollment_code_lifetime_seconds", "3600")},
		},
		{
			config:     cfg(`{ ami = "ami-2" }`, "enrollment_code_lifetime_seconds = 3600"),
			planChecks: append(expectUpdate("definednet_host.h"), unknownCode),
			checks: []resource.TestCheckFunc{codeIs(3), func(*terraform.State) error {
				if c := codes(); c[2].LifetimeSeconds != 3600 || seen[len(seen)-1] == seen[len(seen)-2] {
					return fmt.Errorf("re-mint got lifetime %d and codes %v", c[2].LifetimeSeconds, seen)
				}
				return nil
			}},
		},
		{
			preConfig:   setBlocked(true),
			config:      cfg(`{ ami = "ami-3" }`, "enrollment_code_lifetime_seconds = 3600"),
			expectError: "ERR_HOST_BLOCKED",
		},
		{
			// The same config now plans the mint again because the failed one left the old triggers in state.
			preConfig:  setBlocked(false),
			config:     cfg(`{ ami = "ami-3" }`, "enrollment_code_lifetime_seconds = 3600"),
			planChecks: append(expectUpdate("definednet_host.h"), unknownCode),
			checks:     []resource.TestCheckFunc{codeIs(4), putsAre(0)},
		},
		{
			// A host change alongside a trigger change still PUTs, once.
			config:     strings.Replace(cfg(`{ ami = "ami-4" }`, "enrollment_code_lifetime_seconds = 3600"), `"pet"`, `"pet-2"`, 1),
			planChecks: append(expectUpdate("definednet_host.h"), unknownCode),
			checks:     []resource.TestCheckFunc{codeIs(5), putsAre(1), resource.TestCheckResourceAttr("definednet_host.h", "name", "pet-2")},
		},
	})
}

// An imported host has no code; a trigger change mints its first one.
func TestHostResource_EnrollmentCode_Imported(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	c, err := client.New(f.URL(), f.apiKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	n, err := c.CreateNetwork(ctx, client.NetworkCreateRequest{Name: "n", CIDRs: []string{"10.10.0.0/16"}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := c.CreateHost(ctx, client.HostCreateRequest{NetworkID: n.ID, Name: "pet", IPAddresses: []string{"10.10.0.0/16"}})
	if err != nil {
		t.Fatal(err)
	}

	cfg := func(triggers string) string {
		return fmt.Sprintf(`
resource "definednet_host" "h" {
  network_id               = %q
  name                     = "pet"
  enrollment_code_triggers = %s
}
`, n.ID, triggers)
	}
	runUnitTest(t, f, []testStep{
		{config: cfg("null"), importState: true, importPersist: true, importResource: "definednet_host.h", importStateID: h.ID},
		{
			config:     cfg("null"),
			planChecks: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
		},
		{
			config:     cfg(`{ ami = "ami-1" }`),
			planChecks: append(expectUpdate("definednet_host.h"), plancheck.ExpectUnknownValue("definednet_host.h", tfjsonpath.New("enrollment_code"))),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrSet("definednet_host.h", "enrollment_code"),
				resource.TestCheckNoResourceAttr("definednet_host.h", "enrollment_code_lifetime_seconds"),
			},
		},
	})
}
