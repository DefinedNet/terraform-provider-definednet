data "definednet_network" "main" {
  name = "Management"
}

output "main_cidrs" {
  value = data.definednet_network.main.cidrs
}
