resource "definednet_domain" "corp" {
  domain_name = "example.com"
}

# Publish the ownership record with your DNS provider, for example Cloudflare:
resource "cloudflare_dns_record" "definednet_verification" {
  zone_id = var.cloudflare_zone_id
  type    = "TXT"
  name    = definednet_domain.corp.verification_record_name
  content = definednet_domain.corp.verification_record_value
  ttl     = 300
}
