package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	fleet "github.com/your-org/Fleet-Terminal/sdk"
)

var (
	_ datasource.DataSource              = &roleDataSource{}
	_ datasource.DataSourceWithConfigure = &roleDataSource{}
)

// NewRoleDataSource is the fleet_role data source factory. It resolves a role by
// name to its UUID (needed to grant roles to service accounts).
func NewRoleDataSource() datasource.DataSource { return &roleDataSource{} }

type roleDataSource struct{ client *fleet.Client }

type roleDataModel struct {
	Name        types.String `tfsdk:"name"`
	ID          types.String `tfsdk:"id"`
	Description types.String `tfsdk:"description"`
	IsBuiltin   types.Bool   `tfsdk:"is_builtin"`
}

func (d *roleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func (d *roleDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *roleDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Look up a Fleet role by name.",
		Attributes: map[string]schema.Attribute{
			"name":        schema.StringAttribute{Required: true, MarkdownDescription: "Role name to look up (exact match)."},
			"id":          schema.StringAttribute{Computed: true, MarkdownDescription: "Role UUID."},
			"description": schema.StringAttribute{Computed: true, MarkdownDescription: "Role description."},
			"is_builtin":  schema.BoolAttribute{Computed: true, MarkdownDescription: "Whether this is a built-in role."},
		},
	}
}

func (d *roleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data roleDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	roles, err := d.client.ListRoles(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Could not list roles", err.Error())
		return
	}
	want := data.Name.ValueString()
	for _, role := range roles {
		if role.Name == want {
			data.ID = types.StringValue(role.ID)
			data.Description = types.StringValue(role.Description)
			data.IsBuiltin = types.BoolValue(role.IsBuiltin)
			resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
			return
		}
	}
	resp.Diagnostics.AddError("Role not found", fmt.Sprintf("No role named %q.", want))
}
