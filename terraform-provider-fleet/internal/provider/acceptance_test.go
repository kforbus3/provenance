package provider

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// Acceptance-test scaffolding.
//
// The schema/metadata tests in provider_test.go run in plain `go test`. The
// helpers below are the entry point for *acceptance* tests — the kind that
// stand up real resources against a live Fleet deployment. They are gated on
// TF_ACC so they never run (and never touch a real server) during a normal
// unit-test pass or in CI.
//
// Writing the actual CRUD acceptance tests (resource.Test with plan/apply/
// import steps) requires the terraform-plugin-testing module. That dependency
// is intentionally not added here yet; when it is, a test looks like:
//
//	import "github.com/hashicorp/terraform-plugin-testing/helper/resource"
//
//	func TestAccHostResource_basic(t *testing.T) {
//	    resource.Test(t, resource.TestCase{
//	        PreCheck:                 func() { testAccPreCheck(t) },
//	        ProtoV6ProviderFactories: testAccProtoV6ProviderFactories,
//	        Steps: []resource.TestStep{
//	            {Config: testAccHostConfig_basic, Check: ...},
//	            {ResourceName: "fleet_host.web", ImportState: true, ImportStateVerify: true},
//	        },
//	    })
//	}
//
// The provider factory and pre-check below are already usable as-is, so adding
// terraform-plugin-testing is the only remaining step.

// testAccProtoV6ProviderFactories wires the provider under test into the
// acceptance-test harness by protocol name ("fleet").
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"fleet": providerserver.NewProtocol6WithError(New("test")()),
}

// testAccPreCheck fails fast (with a clear message) when the environment is not
// set up for acceptance testing. Acceptance tests hit a real server, so they
// require TF_ACC plus valid Fleet credentials.
func testAccPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance tests skipped; set TF_ACC=1 to run them")
	}
	for _, v := range []string{"FLEET_URL", "FLEET_API_TOKEN"} {
		if os.Getenv(v) == "" {
			t.Fatalf("%s must be set for acceptance tests", v)
		}
	}
}

// TestAccProviderFactory is a smoke test that the acceptance-test plumbing
// compiles and the provider server can be constructed. It runs in a normal
// `go test` pass (no TF_ACC, no network).
func TestAccProviderFactory(t *testing.T) {
	factory, ok := testAccProtoV6ProviderFactories["fleet"]
	if !ok {
		t.Fatal("no provider factory registered for \"fleet\"")
	}
	if _, err := factory(); err != nil {
		t.Fatalf("building provider server: %v", err)
	}
}
