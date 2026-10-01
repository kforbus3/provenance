package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestCanonicalCIDR(t *testing.T) {
	for in, wantErr := range map[string]bool{
		"10.0.2.0/24": false, "10.0.2.40/32": false, "2001:db8::/120": false,
		"10.0.2.5/24": true, "10.0.2.40": true, "nonsense": true,
	} {
		resp := &validator.StringResponse{}
		canonicalCIDR{}.ValidateString(context.Background(), validator.StringRequest{
			Path: path.Root("cidr"), ConfigValue: types.StringValue(in),
		}, resp)
		if got := resp.Diagnostics.HasError(); got != wantErr {
			t.Errorf("%q: error=%v, want %v (%v)", in, got, wantErr, resp.Diagnostics)
		}
	}
}
