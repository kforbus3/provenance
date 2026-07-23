package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	fleet "github.com/your-org/Fleet-Terminal/sdk"
)

// clientFromProviderData extracts the configured *fleet.Client passed from the
// provider's Configure. It is nil during validation (providerData unset), which
// callers must tolerate.
func clientFromProviderData(providerData any, diags *diag.Diagnostics) *fleet.Client {
	if providerData == nil {
		return nil
	}
	client, ok := providerData.(*fleet.Client)
	if !ok {
		diags.AddError("Unexpected provider data",
			fmt.Sprintf("Expected *fleet.Client, got %T. This is a provider bug.", providerData))
		return nil
	}
	return client
}

// stringSliceToList converts a []string to a Terraform list value, mapping nil to
// an empty (non-null) list so it round-trips cleanly.
func stringSliceToList(ctx context.Context, in []string, diags *diag.Diagnostics) types.List {
	if in == nil {
		in = []string{}
	}
	list, d := types.ListValueFrom(ctx, types.StringType, in)
	diags.Append(d...)
	return list
}

// listToStringSlice converts a Terraform list value to a []string. Null/unknown
// lists yield nil.
func listToStringSlice(ctx context.Context, list types.List, diags *diag.Diagnostics) []string {
	if list.IsNull() || list.IsUnknown() {
		return nil
	}
	var out []string
	diags.Append(list.ElementsAs(ctx, &out, false)...)
	return out
}

// strOrNull maps an empty server string to a null attribute, so an optional field
// the caller left unset does not perpetually diff against the server's "".
func strOrNull(s string) types.String {
	if s == "" {
		return types.StringNull()
	}
	return types.StringValue(s)
}

// listOrNull maps an empty server slice to a null list, for the same reason.
func listOrNull(ctx context.Context, in []string, diags *diag.Diagnostics) types.List {
	if len(in) == 0 {
		return types.ListNull(types.StringType)
	}
	return stringSliceToList(ctx, in, diags)
}
