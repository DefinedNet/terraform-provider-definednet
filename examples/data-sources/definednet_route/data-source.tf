data "definednet_route" "dc" {
  name = "datacenter"
}

resource "definednet_tag" "dc_clients" {
  name                = "access:datacenter"
  route_subscriptions = [data.definednet_route.dc.id]
}
