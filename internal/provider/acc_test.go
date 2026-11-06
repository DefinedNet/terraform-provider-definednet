package provider

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

// accPrefix starts the name of every object the acceptance tests create, so
// the sweeper can tell them apart from anything else in the org.
const accPrefix = "tf-acc"

// envAccDomain names a domain whose TXT record you control. The default's
// record lives in DefinedNet/ansible and matches only the shared test org,
// since the verification value differs per org.
const envAccDomain = "DEFINEDNET_ACC_DOMAIN"

func TestMain(m *testing.M) {
	resource.TestMain(m)
}

func accDomain() string {
	if d := os.Getenv(envAccDomain); d != "" {
		return d
	}
	return "tf-acc.test.undefined.works"
}

// accName returns a unique object name. Tags must be key:value, so they use
// accPrefix as the key.
func accName() string { return accPrefix + "-" + acctest.RandString(8) }

func accTagName() string { return accPrefix + ":" + acctest.RandString(8) }

func testAccPreCheck(t *testing.T) {
	if os.Getenv(envAPIKey) == "" {
		t.Fatal(envAPIKey + " must be set for acceptance tests")
	}
}

func testAccClient() (*client.Client, error) {
	return client.New(os.Getenv(envEndpoint), os.Getenv(envAPIKey))
}

// runAccTest runs steps against the API named by the provider's environment
// variables.
func runAccTest(t *testing.T, steps []testStep) {
	t.Helper()
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testProviderFactories,
		CheckDestroy:             testAccCheckDestroyed,
		Steps:                    buildSteps("", steps),
	})
}

// runAccRemovedOutOfBandTest applies cfg, deletes addr through the client,
// and expects the next plan to recreate it rather than fail the refresh.
func runAccRemovedOutOfBandTest(t *testing.T, cfg, addr string, remove func(c *client.Client, id string) error) {
	t.Helper()
	var id string
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: testProviderFactories,
		CheckDestroy:             testAccCheckDestroyed,
		Steps: []resource.TestStep{
			{
				Config: cfg,
				Check: func(s *terraform.State) error {
					r, ok := s.RootModule().Resources[addr]
					if !ok {
						return fmt.Errorf("%s not in state", addr)
					}
					id = r.Primary.ID
					return nil
				},
			},
			{
				PreConfig: func() {
					c, err := testAccClient()
					if err == nil {
						err = remove(c, id)
					}
					if err != nil {
						t.Fatalf("removing %s: %v", id, err)
					}
				},
				Config:           cfg,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: expectCreate(addr)},
			},
		},
	})
}

// testAccCheckDestroyed confirms the API no longer has any object left in state.
func testAccCheckDestroyed(s *terraform.State) error {
	c, err := testAccClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	for addr, r := range s.RootModule().Resources {
		if strings.HasPrefix(addr, "data.") {
			continue
		}
		id := r.Primary.ID
		switch r.Type {
		case "definednet_network":
			_, err = c.GetNetwork(ctx, id)
		case "definednet_role":
			_, err = c.GetRole(ctx, id)
		case "definednet_route":
			_, err = c.GetRoute(ctx, id)
		case "definednet_tag":
			_, err = c.GetTag(ctx, id)
		case "definednet_domain":
			_, err = c.GetDomain(ctx, id)
		case "definednet_endpoint_oidc_provider":
			_, err = c.GetEndpointOIDCProvider(ctx, id)
		case "definednet_join_key":
			_, err = c.GetJoinKey(ctx, id)
		case "definednet_host":
			_, err = c.GetHost(ctx, id)
		default:
			continue
		}
		if err == nil {
			return fmt.Errorf("%s %s still exists", addr, id)
		}
		if !client.IsNotFound(err) {
			return fmt.Errorf("checking %s %s: %w", addr, id, err)
		}
	}
	return nil
}

func init() {
	resource.AddTestSweepers("definednet", &resource.Sweeper{Name: "definednet", F: sweep})
}

type sweepTarget struct {
	kind, id string
	del      func(context.Context, string) error
}

// sweep deletes every object the acceptance tests could have leaked. Objects
// reference each other in cycles (tags subscribe to routes, route rules allow
// roles, role rules allow tags), so no single delete order works; it retries
// in passes until a pass deletes nothing.
func sweep(string) error {
	c, err := testAccClient()
	if err != nil {
		return err
	}
	ctx := context.Background()
	for {
		targets, err := sweepTargets(ctx, c)
		if err != nil {
			return err
		}
		if len(targets) == 0 {
			return nil
		}
		var errs []error
		deleted := 0
		for _, tg := range targets {
			if err := tg.del(ctx, tg.id); err != nil && !client.IsNotFound(err) {
				errs = append(errs, fmt.Errorf("%s %s: %w", tg.kind, tg.id, err))
				continue
			}
			log.Printf("[INFO] swept %s %s", tg.kind, tg.id)
			deleted++
		}
		if deleted == 0 {
			return errors.Join(errs...)
		}
	}
}

func sweepTargets(ctx context.Context, c *client.Client) ([]sweepTarget, error) {
	ours := func(name string) bool { return strings.HasPrefix(name, accPrefix) }
	var out []sweepTarget

	// Hosts and join keys hold their network and role, so they go first.
	hosts, err := c.ListHosts(ctx)
	if err != nil {
		return nil, err
	}
	for _, h := range hosts {
		if ours(h.Name) {
			out = append(out, sweepTarget{"host", h.ID, c.DeleteHost})
		}
	}
	// An organization without join keys enabled answers 404, which means there
	// is nothing to sweep.
	joinKeys, err := c.ListJoinKeys(ctx)
	if err != nil && !client.IsNotFound(err) {
		return nil, err
	}
	for _, k := range joinKeys {
		if ours(k.Name) {
			out = append(out, sweepTarget{"join key", k.ID, c.DeleteJoinKey})
		}
	}
	// OIDC providers go early: they hold the network, role and domain.
	providers, err := c.ListEndpointOIDCProviders(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range providers {
		if ours(p.Name) {
			out = append(out, sweepTarget{"endpoint OIDC provider", p.ID, c.DeleteEndpointOIDCProvider})
		}
	}
	domains, err := c.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	for _, d := range domains {
		if ours(d.DomainName) || d.DomainName == accDomain() {
			out = append(out, sweepTarget{"domain", d.ID, c.DeleteDomain})
		}
	}
	roles, err := c.ListRoles(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range roles {
		if ours(r.Name) {
			out = append(out, sweepTarget{"role", r.ID, c.DeleteRole})
		}
	}
	tags, err := c.ListTags(ctx)
	if err != nil {
		return nil, err
	}
	for _, tg := range tags {
		if ours(tg.Name) {
			out = append(out, sweepTarget{"tag", tg.Name, c.DeleteTag})
		}
	}
	routes, err := c.ListRoutes(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range routes {
		if ours(r.Name) {
			out = append(out, sweepTarget{"route", r.ID, c.DeleteRoute})
		}
	}
	networks, err := c.ListNetworks(ctx)
	if err != nil {
		return nil, err
	}
	for _, n := range networks {
		if ours(n.Name) {
			out = append(out, sweepTarget{"network", n.ID, c.DeleteNetwork})
		}
	}
	return out, nil
}
