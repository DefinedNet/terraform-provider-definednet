resource "definednet_role" "admin" {
  name        = "admin"
  description = "Operators with SSH access everywhere"
}

resource "definednet_role" "web" {
  name = "web"

  firewall_rules = [
    {
      protocol    = "TCP"
      description = "https from anyone"
      port_range  = { from = 443, to = 443 }
    },
    {
      protocol        = "TCP"
      description     = "ssh from admins in prod"
      allowed_role_id = definednet_role.admin.id
      allowed_tags    = ["env:prod"]
      port_range      = { from = 22, to = 22 }
    },
    {
      protocol        = "ANY"
      description     = "anything between web servers"
      allowed_role_id = "self" # Terraform cannot reference definednet_role.web.id from inside itself
    },
    {
      protocol = "ICMP"
    },
  ]
}
