package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/DefinedNet/terraform-provider-definednet/internal/provider"
)

// version is set by the build (e.g. -ldflags "-X main.version=1.2.3").
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider in debug mode for attaching a debugger")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/definednet/definednet",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
