resource "definednet_network" "main" {
  name                  = "Management"
  description           = "Ops team management network"
  ipv4_cidr             = "100.100.0.0/22"
  lighthouses_as_relays = true
}
