package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

func TestProviderSchema(t *testing.T) {
	var resp provider.SchemaResponse
	New("test")().Schema(context.Background(), provider.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("provider schema diagnostics: %v", resp.Diagnostics)
	}
	if _, ok := resp.Schema.Attributes["endpoint"]; !ok {
		t.Error("provider schema missing endpoint attribute")
	}
}

func TestResourceSchemas(t *testing.T) {
	factories := map[string]func() resource.Resource{
		"host":                  NewHostResource,
		"group":                 NewGroupResource,
		"service_account":       NewServiceAccountResource,
		"service_account_token": NewServiceAccountTokenResource,
	}
	for name, f := range factories {
		var resp resource.SchemaResponse
		f().Schema(context.Background(), resource.SchemaRequest{}, &resp)
		if resp.Diagnostics.HasError() {
			t.Errorf("%s resource schema diagnostics: %v", name, resp.Diagnostics)
		}
		if _, ok := resp.Schema.Attributes["id"]; !ok {
			t.Errorf("%s resource schema missing id attribute", name)
		}
	}
}

func TestDataSourceSchemas(t *testing.T) {
	var resp datasource.SchemaResponse
	NewRoleDataSource().Schema(context.Background(), datasource.SchemaRequest{}, &resp)
	if resp.Diagnostics.HasError() {
		t.Errorf("role data source schema diagnostics: %v", resp.Diagnostics)
	}
}

func TestProviderMetadata(t *testing.T) {
	var resp provider.MetadataResponse
	New("1.2.3")().Metadata(context.Background(), provider.MetadataRequest{}, &resp)
	if resp.TypeName != "fleet" {
		t.Errorf("TypeName = %q, want fleet", resp.TypeName)
	}
	if resp.Version != "1.2.3" {
		t.Errorf("Version = %q, want 1.2.3", resp.Version)
	}
}
