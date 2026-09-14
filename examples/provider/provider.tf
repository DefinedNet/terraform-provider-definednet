terraform {
  required_providers {
    definednet = {
      source = "johnmaguire/definednet"
    }
  }
}

# api_key can also come from the DEFINEDNET_API_KEY environment variable.
provider "definednet" {
  api_key = var.definednet_api_key
}
