package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	prov "github.com/kforbus3/provenance/sdk"
)

// Ensure the implementation satisfies the provider interface.
var _ provider.Provider = &provenanceProvider{}

type provenanceProvider struct {
	version string
}

// New returns a provider factory for the given build version.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &provenanceProvider{version: version}
	}
}

// providerModel maps provider configuration.
type providerModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	Token    types.String `tfsdk:"token"`
}

func (p *provenanceProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "fleet"
	resp.Version = p.version
}

func (p *provenanceProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manage a Provenance deployment as code. Authenticates with a service-account API token.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "Base URL of the Provenance deployment, e.g. `https://provenance.example.com`. Falls back to the `PROV_URL` environment variable.",
				Optional:            true,
			},
			"token": schema.StringAttribute{
				MarkdownDescription: "Service-account API token (`flt_...`). Falls back to the `PROV_API_TOKEN` environment variable.",
				Optional:            true,
				Sensitive:           true,
			},
		},
	}
}

func (p *provenanceProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := os.Getenv("PROV_URL")
	if !cfg.Endpoint.IsNull() {
		endpoint = cfg.Endpoint.ValueString()
	}
	token := os.Getenv("PROV_API_TOKEN")
	if !cfg.Token.IsNull() {
		token = cfg.Token.ValueString()
	}

	if endpoint == "" {
		resp.Diagnostics.AddAttributeError(path.Root("endpoint"),
			"Missing Provenance endpoint",
			"Set the provider `endpoint` or the PROV_URL environment variable.")
	}
	if token == "" {
		resp.Diagnostics.AddAttributeError(path.Root("token"),
			"Missing Provenance API token",
			"Set the provider `token` or the PROV_API_TOKEN environment variable.")
	}
	if resp.Diagnostics.HasError() {
		return
	}

	client, err := prov.New(endpoint, prov.WithToken(token), prov.WithUserAgent("terraform-provider-provenance/"+p.version))
	if err != nil {
		resp.Diagnostics.AddError("Invalid Provenance client configuration", err.Error())
		return
	}
	// Make the client available to resources and data sources.
	resp.ResourceData = client
	resp.DataSourceData = client
}

func (p *provenanceProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewHostResource,
		NewGroupResource,
		NewServiceAccountResource,
		NewServiceAccountTokenResource,
	}
}

func (p *provenanceProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewRoleDataSource,
	}
}
