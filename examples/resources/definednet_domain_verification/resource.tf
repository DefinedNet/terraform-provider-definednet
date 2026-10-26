resource "definednet_domain_verification" "corp" {
  domain_id = definednet_domain.corp.id

  # The TXT record must exist before verification can succeed.
  depends_on = [cloudflare_dns_record.definednet_verification]

  timeouts {
    create = "15m"
  }
}

