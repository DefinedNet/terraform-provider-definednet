package provider

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"

	"github.com/DefinedNet/terraform-provider-definednet/internal/client"
)

// testAccPreCheckJoinKeys skips when the organization does not have join
// keys enabled: the API's JOIN_KEYS feature flag guard answers every
// /v1/join-keys route with 404 ERR_NOT_FOUND.
func testAccPreCheckJoinKeys(t *testing.T) {
	if os.Getenv(resource.EnvTfAcc) == "" {
		return // resource.Test skips the test itself
	}
	testAccPreCheck(t)
	c, err := testAccClient()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListJoinKeys(context.Background()); client.IsNotFound(err) {
		t.Skip("join keys are not enabled for this organization (JOIN_KEYS feature flag): GET /v1/join-keys returned 404")
	} else if err != nil {
		t.Fatal(err)
	}
}

func accJoinKeyBase() string {
	return fmt.Sprintf(`
resource "definednet_network" "n" {
  name      = %q
  ipv4_cidr = "192.168.148.0/22"
}

resource "definednet_role" "r" {
  name = %q
}
`, accName(), accName())
}

func TestAccJoinKeyResource(t *testing.T) {
	testAccPreCheckJoinKeys(t)
	base := accJoinKeyBase()
	name, tag := accName(), accTagName()
	expiry := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	later := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	key := func(name, extra string) string {
		return base + fmt.Sprintf(`
resource "definednet_join_key" "k" {
  name              = %q
  network_id        = definednet_network.n.id
  role_id           = definednet_role.r.id
  tags              = [%q]
  auto_assign_cidrs = [definednet_network.n.ipv4_cidr]
  %s
}
`, name, tag, extra)
	}
	first := key(name, fmt.Sprintf("expires_at = %q", expiry))
	runAccTest(t, []testStep{
		{
			config: first,
			checks: []resource.TestCheckFunc{
				resource.TestMatchResourceAttr("definednet_join_key.k", "id", regexp.MustCompile(`^dnjoin-`)),
				resource.TestMatchResourceAttr("definednet_join_key.k", "token", regexp.MustCompile(`^dnjoin-`)),
				resource.TestCheckResourceAttr("definednet_join_key.k", "expires_at", expiry),
				resource.TestCheckResourceAttr("definednet_join_key.k", "auto_assign_cidrs.#", "1"),
				resource.TestCheckTypeSetElemAttr("definednet_join_key.k", "auto_assign_cidrs.*", "192.168.148.0/22"),
			},
		},
		{
			// The API returns the token only on create.
			importState: true, importResource: "definednet_join_key.k",
			importVerifyIgnore: []string{"token"},
		},
		{
			config:     key(name+"-renamed", fmt.Sprintf("expires_at = %q", later)),
			planChecks: expectUpdate("definednet_join_key.k"),
			checks: []resource.TestCheckFunc{
				resource.TestCheckResourceAttr("definednet_join_key.k", "name", name+"-renamed"),
				resource.TestCheckResourceAttr("definednet_join_key.k", "expires_at", later),
			},
		},
		{
			config:     key(name+"-renamed", ""),
			planChecks: expectUpdate("definednet_join_key.k"),
			checks:     []resource.TestCheckFunc{resource.TestCheckNoResourceAttr("definednet_join_key.k", "expires_at")},
		},
	})
}

func TestAccJoinKeyResource_RemovedOutOfBand(t *testing.T) {
	testAccPreCheckJoinKeys(t)
	runAccRemovedOutOfBandTest(t, accJoinKeyBase()+fmt.Sprintf(`
resource "definednet_join_key" "k" {
  name       = %q
  network_id = definednet_network.n.id
}`, accName()), "definednet_join_key.k", func(c *client.Client, id string) error {
		return c.DeleteJoinKey(context.Background(), id)
	})
}
