# Preferred: the secret never enters plan or state (Terraform 1.11+ / OpenTofu 1.11+).
# Bump client_secret_wo_version whenever the secret is rotated.
resource "definednet_endpoint_oidc_provider" "okta" {
  name                     = "Okta"
  issuer_url               = "https://corp.okta.com"
  client_id                = var.okta_client_id
  client_secret_wo         = var.okta_client_secret
  client_secret_wo_version = 1

  network_id          = definednet_network.main.id
  role_id             = definednet_role.employee.id
  auth_validity_hours = 168

  # Reference the verification, not the domain, so the provider is created
  # only after the domain is verified.
  domain_id = definednet_domain_verification.corp.domain_id
  enabled   = true
}

# Alternative for older Terraform: the secret is stored (sensitive) in state.
resource "definednet_endpoint_oidc_provider" "google" {
  name          = "Google"
  issuer_url    = "https://accounts.google.com"
  client_id     = var.google_client_id
  client_secret = var.google_client_secret
  network_id    = definednet_network.main.id
}
