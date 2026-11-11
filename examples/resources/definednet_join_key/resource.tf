# One key enrolls a whole fleet; the hosts it creates are not managed by Terraform.
resource "definednet_join_key" "web" {
  name       = "web"
  network_id = definednet_network.main.id
  role_id    = definednet_role.web.id
  tags       = ["env:prod", "service:web"]

  # Give enrolled hosts an IPv4 address too; IPv6 is always assigned.
  auto_assign_cidrs = [definednet_network.main.ipv4_cidr]

  expires_at = "2027-01-01T00:00:00Z"
}

# The token is a long-lived secret; hand it to your image or instance
# bootstrap the way you handle other credentials.
output "web_join_key" {
  value     = definednet_join_key.web.token
  sensitive = true
}
