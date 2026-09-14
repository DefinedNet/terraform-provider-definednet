resource "definednet_tag" "dev" {
  name = "env:dev"
}

resource "definednet_tag" "prod" {
  name        = "env:prod"
  description = "Production hosts"

  # Give prod higher precedence than dev for config overrides.
  after = definednet_tag.dev.name

  # Values are JSON: use jsonencode() for every type.
  config_overrides = [
    { key = "lighthouse.dns.host", value = jsonencode("0.0.0.0") },
    { key = "lighthouse.dns.port", value = jsonencode(53) },
    { key = "definednet.dns.resolver_addrs", value = jsonencode(["10.0.0.53"]) },
  ]

  # Every host with this tag is subscribed to the datacenter route.
  route_subscriptions = [definednet_route.datacenter.id]

  firewall_rules = [
    {
      protocol     = "TCP"
      description  = "node exporter from monitoring hosts"
      allowed_tags = ["role:monitoring"]
      port_range   = { from = 9100, to = 9100 }
    },
  ]
}
