resource "definednet_route" "datacenter" {
  name           = "datacenter"
  description    = "On-prem subnets behind the office router"
  router_host_id = "host-24NVITKMNU3CYCEDNFWKAOBX7I"

  routable_cidrs = {
    "192.168.14.0/24" = { install = true }
    "192.168.15.0/24" = { install = true }
  }

  firewall_rules = [
    {
      local_cidr      = "192.168.14.56/32"
      protocol        = "TCP"
      description     = "ssh to the bastion from admins"
      allowed_role_id = definednet_role.admin.id
      port_range      = { from = 22, to = 22 }
    },
    {
      local_cidr = "ANY"
      protocol   = "ICMP"
    },
  ]
}
