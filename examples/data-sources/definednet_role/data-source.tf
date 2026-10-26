data "definednet_role" "admin" {
  name = "admin"
}

# Allow SSH from existing admins without managing their role here.
resource "definednet_role" "bastion" {
  name = "bastion"

  firewall_rules = [
    {
      protocol        = "TCP"
      allowed_role_id = data.definednet_role.admin.id
      port_range      = { from = 22, to = 22 }
    },
  ]
}
