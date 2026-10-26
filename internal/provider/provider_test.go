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

func TestProvider_InvalidAPIKey(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	runUnitTest(t, nil, []testStep{{
		config: fmt.Sprintf(`
provider "definednet" {
  endpoint = %q
  api_key  = "wrong"
}

data "definednet_network" "x" {
  id = "network-X"
}`, f.URL()),
		// The request id from the fake's X-Request-ID header must reach the diagnostic.
		expectError: `(?s)Invalid api_key.*invalid or revoked.*\(request id req-`,
	}})
}

func TestProvider_SkipCredentialsValidation(t *testing.T) {
	f := newFakeAPI()
	defer f.Close()
	runUnitTest(t, nil, []testStep{{
		config: fmt.Sprintf(`
provider "definednet" {
  endpoint                    = %q
  api_key                     = "wrong"
  skip_credentials_validation = true
}

data "definednet_network" "x" {
  id = "network-X"
}`, f.URL()),
		// Configure must not call whoami, so the 401 surfaces from the data source instead.
		expectError: `Unable to read network`,
	}})
}
