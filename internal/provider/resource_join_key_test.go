package provider

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

const joinKeyBase = `
resource "definednet_network" "n" {
  name      = "n"
  ipv4_cidr = "10.10.0.0/16"
}

resource "definednet_role" "r" {
  name = "r"
}
`

func onlyJoinKey(f *fakeAPI) *client.JoinKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.joinKeys {
		return k
	}
	return nil
}

// expectJoinKeyPatches checks the raw PATCH bodies the fake received so far.
func expectJoinKeyPatches(f *fakeAPI, want ...string) resource.TestCheckFunc {
	return func(*terraform.State) error {
		f.mu.Lock()
		defer f.mu.Unlock()
		if !slices.Equal(f.joinKeyPatches, want) {
			return fmt.Errorf("PATCH bodies %q, want %q", f.joinKeyPatches, want)
		}
		return nil
	}
}

// captureAttr stores an attribute's value, and checkAttr compares a later
// value against it, so steps can assert a value was kept or replaced.
func captureAttr(addr, key string, into *string) resource.TestCheckFunc {
	return resource.TestCheckResourceAttrWith(addr, key, func(v string) error {
		*into = v
		return nil
	})
}

func checkAttr(addr, key string, prev *string, same bool) resource.TestCheckFunc {
	return resource.TestCheckResourceAttrWith(addr, key, func(v string) error {
		if (v == *prev) != same {
			return fmt.Errorf("%s.%s = %q, previous %q, want same=%v", addr, key, v, *prev, same)
		}
		return nil
	})
}

func TestJoinKeyResource(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	expiry := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	later := expiry.Add(24 * time.Hour).Format(time.RFC3339)

	key := func(name, extra string) string {
		return joinKeyBase + fmt.Sprintf(`
resource "definednet_join_key" "k" {
  name       = %q
  network_id = definednet_network.n.id
  role_id    = definednet_role.r.id
  tags       = ["env:prod", "team:infra"]
  %s
}
`, name, extra)
	}
	var token string
	runUnitTest(t, f, []testStep{
		{
			config: key("fleet", fmt.Sprintf(`
  auto_assign_cidrs = [definednet_network.n.ipv4_cidr]
  expires_at        = %q`, expiry.Format(time.RFC3339))),
			checks: []resource.TestCheckFunc{
				resource.TestMatchResourceAttr("definednet_join_key.k", "id", regexp.MustCompile(`^dnjoin-`)),
				resource.TestMatchResourceAttr("definednet_join_key.k", "token", regexp.MustCompile(`^dnjoin-.+-.+`)),
				captureAttr("definednet_join_key.k", "token", &token),
				resource.TestCheckResourceAttr("definednet_join_key.k", "expires_at", expiry.Format(time.RFC3339)),
				resource.TestCheckResourceAttr("definednet_join_key.k", "tags.#", "2"),
				// The API adds the network's IPv6 prefix; state holds only the IPv4 opt-in.
				resource.TestCheckResourceAttr("definednet_join_key.k", "auto_assign_cidrs.#", "1"),
				resource.TestCheckTypeSetElemAttr("definednet_join_key.k", "auto_assign_cidrs.*", "10.10.0.0/16"),
				resource.TestCheckResourceAttrPair("definednet_join_key.k", "role_id", "definednet_role.r", "id"),
			},
		},
		{
			// The API returns the token only on create.
			importState: true, importResource: "definednet_join_key.k",
			importVerifyIgnore: []string{"token"},
		},
		{
			// A rename alone must not re-send the expiry, which fails once it has passed.
			config:     key("fleet-renamed", fmt.Sprintf("expires_at = %q", expiry.Format(time.RFC3339))),
			planChecks: expectUpdate("definednet_join_key.k"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_join_key.k", "name", "fleet-renamed"),
				resource.TestCheckResourceAttr("definednet_join_key.k", "auto_assign_cidrs.#", "1"),
				checkAttr("definednet_join_key.k", "token", &token, true),
				expectJoinKeyPatches(f, `{"name":"fleet-renamed"}`),
			},
		},
		{
			config:     key("fleet-renamed", fmt.Sprintf("expires_at = %q", later)),
			planChecks: expectUpdate("definednet_join_key.k"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_join_key.k", "expires_at", later),
				expectJoinKeyPatches(f, `{"name":"fleet-renamed"}`, `{"expiresAt":"`+later+`"}`),
			},
		},
		{
			config:     key("fleet-renamed", ""),
			planChecks: expectUpdate("definednet_join_key.k"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckNoResourceAttr("definednet_join_key.k", "expires_at"),
				expectJoinKeyPatches(f, `{"name":"fleet-renamed"}`, `{"expiresAt":"`+later+`"}`, `{"expiresAt":null}`),
				checkAttr("definednet_join_key.k", "token", &token, true),
			},
		},
		{
			// The shape is immutable: a tag change replaces the key and its token.
			config:     strings.Replace(key("fleet-renamed", ""), `"team:infra"`, `"team:ops"`, 1),
			planChecks: expectReplace("definednet_join_key.k"),
			checks: []resource.TestCheckFunc{
				checkAttr("definednet_join_key.k", "token", &token, false),
				resource.TestCheckTypeSetElemAttr("definednet_join_key.k", "tags.*", "team:ops"),
			},
		},
		{
			// The tag change above dropped IPv4 (the default on this network); opting
			// back in is a shape change too.
			config:     strings.Replace(key("fleet-renamed", "auto_assign_cidrs = [definednet_network.n.ipv4_cidr]"), `"team:infra"`, `"team:ops"`, 1),
			planChecks: expectReplace("definednet_join_key.k"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_join_key.k", "auto_assign_cidrs.#", "1"),
				func(*terraform.State) error {
					if got := onlyJoinKey(f).AutoAssignCIDRs; !slices.Equal(got, []string{"10.10.0.0/16", "fd00:1234:5678:1::/80"}) {
						return fmt.Errorf("API holds autoAssignCIDRs %v", got)
					}
					return nil
				},
			},
		},
		{
			// An explicit empty set declines IPv4.
			config:     strings.Replace(key("fleet-renamed", "auto_assign_cidrs = []"), `"team:infra"`, `"team:ops"`, 1),
			planChecks: expectReplace("definednet_join_key.k"),
			checks:     []resource.TestCheckFunc{resource.TestCheckResourceAttr("definednet_join_key.k", "auto_assign_cidrs.#", "0")},
		},
	})
}

// Moving a key to another network with auto_assign_cidrs omitted must not
// carry the old network's IPv4 prefix into the replacement.
func TestJoinKeyResource_NetworkChange(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	cfg := func(network string) string {
		return joinKeyBase + `
resource "definednet_network" "m" {
  name      = "m"
  ipv4_cidr = "10.20.0.0/16"
}

resource "definednet_join_key" "k" {
  name       = "k"
  network_id = definednet_network.` + network + `.id
}
`
	}
	runUnitTest(t, f, []testStep{
		{config: cfg("n"), checks: []resource.TestCheckFunc{resource.TestCheckResourceAttr("definednet_join_key.k", "auto_assign_cidrs.#", "0")}},
		{
			preConfig: func() { onlyJoinKey(f).AutoAssignCIDRs = []string{"10.10.0.0/16", "fd00:1234:5678:1::/80"} },
			config:    cfg("n"),
			// IPv4 added outside Terraform is accepted when the attribute is omitted.
			checks: []resource.TestCheckFunc{resource.TestCheckResourceAttr("definednet_join_key.k", "auto_assign_cidrs.#", "1")},
		},
		{
			config:     cfg("m"),
			planChecks: expectReplace("definednet_join_key.k"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttrPair("definednet_join_key.k", "network_id", "definednet_network.m", "id"),
				resource.TestCheckResourceAttr("definednet_join_key.k", "auto_assign_cidrs.#", "0"),
			},
		},
	})
}

// An expiry changed outside Terraform shows as drift and is put back.
func TestJoinKeyResource_ExpiryDrift(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	expiry := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	cfg := joinKeyBase + fmt.Sprintf(`
resource "definednet_join_key" "k" {
  name       = "k"
  network_id = definednet_network.n.id
  expires_at = %q
}
`, expiry)
	runUnitTest(t, f, []testStep{
		{config: cfg},
		{
			preConfig:  func() { onlyJoinKey(f).ExpiresAt = nil },
			config:     cfg,
			planChecks: expectUpdate("definednet_join_key.k"),
			checks:     []resource.TestCheckFunc{resource.TestCheckResourceAttr("definednet_join_key.k", "expires_at", expiry)},
		},
	})
}

// Renaming an expired key leaves expiresAt out of the PATCH, since the API
// rejects past expiries.
func TestJoinKeyResource_ExpiredRename(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	future := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	past := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	key := func(name string, expiry time.Time) string {
		return joinKeyBase + fmt.Sprintf(`
resource "definednet_join_key" "k" {
  name       = %q
  network_id = definednet_network.n.id
  expires_at = %q
}
`, name, expiry.Format(time.RFC3339))
	}
	runUnitTest(t, f, []testStep{
		{config: key("k", future)},
		{
			preConfig:  func() { onlyJoinKey(f).ExpiresAt = &past },
			config:     key("k2", past),
			planChecks: expectUpdate("definednet_join_key.k"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_join_key.k", "name", "k2"),
				expectJoinKeyPatches(f, `{"name":"k2"}`),
			},
		},
	})
}

func TestJoinKeyResource_Validation(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	for _, tc := range []struct{ body, want string }{
		{`name = "Fleet"`, "must contain only lowercase letters"},
		{`name = "-fleet"`, "must not start or end with a hyphen"},
		{`name = "` + strings.Repeat("a", 55) + `"`, "string length must be between 1 and 54"},
		{`name = "k"
expires_at = "2030-01-01T00:00:00.5Z"`, "RFC 3339 timestamp with whole seconds"},
		{`name = "k"
expires_at = "2030-01-01"`, "RFC 3339 timestamp with whole seconds"},
		{`name = "k"
expires_at = "2030-01-01T02:00:00+02:00"`, "must be a UTC RFC 3339 timestamp"},
		{`name = "k"
tags = ["nocolon"]`, "must be a key:value tag"},
		{`name = "k"
auto_assign_cidrs = ["fd00::/64"]`, "must be an IPv4 network"},
	} {
		runUnitTest(t, f, []testStep{{
			config:      "resource \"definednet_join_key\" \"k\" {\nnetwork_id = \"network-X\"\n" + tc.body + "\n}",
			expectError: tc.want,
		}})
	}
}

func TestJoinKeyResource_APIErrors(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	runUnitTest(t, f, []testStep{
		{
			config: joinKeyBase + `
resource "definednet_join_key" "a" {
  name       = "dup"
  network_id = definednet_network.n.id
}

resource "definednet_join_key" "b" {
  name       = "dup"
  network_id = definednet_network.n.id
  depends_on = [definednet_join_key.a]
}`,
			expectError: "bring it under management with terraform import",
		},
		{
			config: joinKeyBase + `
resource "definednet_join_key" "k" {
  name       = "k"
  network_id = definednet_network.n.id
  expires_at = "2001-01-01T00:00:00Z"
}`,
			expectError: "must be in the future",
		},
	})
}

func TestJoinKeyResource_CertV1EmptyAutoAssign(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	v1 := f.addCertV1Network("10.20.0.0/16")

	key := func(network, extra string) string {
		return joinKeyBase + fmt.Sprintf(`
resource "definednet_join_key" "k" {
  name       = "k"
  network_id = %s
  %s
}`, network, extra)
	}
	runUnitTest(t, f, []testStep{
		{
			config:      key(fmt.Sprintf("%q", v1), "auto_assign_cidrs = []"),
			expectError: `Empty auto_assign_cidrs on a certificate version 1 network(?s:.*)auto_assign_cidrs = \[\]`,
		},
		{
			config: key(fmt.Sprintf("%q", v1), ""),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_join_key.k", "auto_assign_cidrs.#", "1"),
				resource.TestCheckTypeSetElemAttr("definednet_join_key.k", "auto_assign_cidrs.*", "10.20.0.0/16"),
			},
		},
		{
			// Rejected before the replacement would delete the existing key.
			config:      key(fmt.Sprintf("%q", v1), "auto_assign_cidrs = []"),
			expectError: "Empty auto_assign_cidrs on a certificate version 1 network",
		},
		{
			// network_id is unknown at plan time, so the check runs in the apply-time re-plan.
			config: key("definednet_network.m.id", "auto_assign_cidrs = []") + `
resource "definednet_network" "m" {
  name      = "m"
  ipv4_cidr = "10.11.0.0/16"
}`,
			planChecks: []plancheck.PlanCheck{plancheck.ExpectUnknownValue("definednet_join_key.k", tfjsonpath.New("network_id"))},
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_join_key.k", "auto_assign_cidrs.#", "0"),
			},
		},
	})
}

// A failed network read must not block plans that change nothing, including
// the plan terraform destroy runs first.
func TestJoinKeyResource_EmptyAutoAssignNetworkUnreadable(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	// Created outside Terraform so that, with networks:read revoked, only the
	// guard reads it.
	network := f.addCertV1Network("10.20.0.0/16")
	f.networks[network].CertVersion = 2

	cfg := func(name string) string {
		return fmt.Sprintf(`
resource "definednet_join_key" "k" {
  name              = %q
  network_id        = %q
  auto_assign_cidrs = []
}`, name, network)
	}
	runUnitTest(t, f, []testStep{
		{config: cfg("k")},
		{
			preConfig:   func() { f.missingScopes = map[string]bool{"networks:read": true} },
			config:      cfg("renamed"),
			expectError: "Unable to read network(?s:.*)networks:read",
		},
		{
			config:     cfg("k"),
			planChecks: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
		},
		{config: cfg("k"), destroy: true},
	})
}

func TestJoinKeyResource_RemovedOutOfBand(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()

	runRemovedOutOfBandTest(t, f, joinKeyBase+`
resource "definednet_join_key" "k" {
  name       = "k"
  network_id = definednet_network.n.id
}`, "definednet_join_key.k", func() { clear(f.joinKeys) })
}

// The acceptance tests must skip, not fail, against an organization without
// the JOIN_KEYS feature flag.
func TestJoinKeyAccPreCheck_SkipsWhenDisabled(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	f.joinKeysDisabled = true
	t.Setenv(resource.EnvTfAcc, "1")
	t.Setenv(envEndpoint, f.URL())
	t.Setenv(envAPIKey, f.apiKey)

	var skipped bool
	t.Run("precheck", func(t *testing.T) {
		defer func() { skipped = t.Skipped() }()
		testAccPreCheckJoinKeys(t)
	})
	if !skipped {
		t.Fatal("precheck did not skip")
	}
}
