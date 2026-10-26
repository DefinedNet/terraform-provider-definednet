data "definednet_tag" "prod" {
  name = "env:prod"
}

output "prod_priority" {
  value = data.definednet_tag.prod.priority
}
