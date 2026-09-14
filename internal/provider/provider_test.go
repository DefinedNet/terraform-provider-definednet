package provider

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

var testProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"definednet": providerserver.NewProtocol6WithError(New("test")()),
}

// providerConfig returns a provider block pointing at the fake API.
func providerConfig(f *fakeAPI) string {
	return fmt.Sprintf(`
provider "definednet" {
  endpoint = %q
  api_key  = %q
}
`, f.URL(), f.apiKey)
}

func TestProvider_MissingAPIKey(t *testing.T) {
	t.Setenv(envAPIKey, "")
	t.Setenv(envEndpoint, "")
	runUnitTest(t, nil, []testStep{{
		config: `
provider "definednet" {
}

data "definednet_network" "x" {
  id = "network-X"
}`,
		expectError: "Missing API key",
	}})
}
