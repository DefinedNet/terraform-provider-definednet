resource "definednet_domain_verification" "corp" {
  domain_id = definednet_domain.corp.id

  # The TXT record must exist before verification can succeed.
  depends_on = [cloudflare_dns_record.definednet_verification]

  timeouts {
    create = "15m"
  }
}

# Reference the verification, not the domain, so the provider is created
# only after the domain is verified.
resource "definednet_endpoint_oidc_provider" "okta" {
  # ...
  domain_id = definednet_domain_verification.corp.domain_id
  enabled   = true
}
