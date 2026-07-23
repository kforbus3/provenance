// terraform-provider-fleet is the Terraform provider for Fleet Terminal. It lets
// you manage Fleet resources — hosts, groups, service accounts, and their tokens —
// as infrastructure-as-code, authenticating with a service-account API token.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/kforbus3/Fleet-Terminal/terraform-provider-fleet/internal/provider"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		// Registry address once published; also the source used in required_providers.
		Address: "registry.terraform.io/kforbus3/fleet",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
