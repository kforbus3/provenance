package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	fleet "github.com/your-org/Fleet-Terminal/sdk"
)

var (
	_ resource.Resource                = &hostResource{}
	_ resource.ResourceWithConfigure   = &hostResource{}
	_ resource.ResourceWithImportState = &hostResource{}
)

// NewHostResource is the fleet_host resource factory.
func NewHostResource() resource.Resource { return &hostResource{} }

type hostResource struct{ client *fleet.Client }

type hostModel struct {
	ID          types.String `tfsdk:"id"`
	Hostname    types.String `tfsdk:"hostname"`
	Description types.String `tfsdk:"description"`
	Environment types.String `tfsdk:"environment"`
	Owner       types.String `tfsdk:"owner"`
	Address     types.String `tfsdk:"address"`
	WGAddress   types.String `tfsdk:"wg_address"`
	SSHPort     types.Int64  `tfsdk:"ssh_port"`
	SSHUser     types.String `tfsdk:"ssh_user"`
	Tags        types.List   `tfsdk:"tags"`
	Enrolled    types.Bool   `tfsdk:"enrolled"`
}

func (r *hostResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_host"
}

func (r *hostResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *hostResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	optComputedString := func(desc string) schema.StringAttribute {
		return schema.StringAttribute{Optional: true, Computed: true, MarkdownDescription: desc}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "A managed host in Fleet.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Host UUID.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"hostname": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Hostname (unique).",
			},
			"description": optComputedString("Free-text description."),
			"environment": optComputedString("Environment label, e.g. production."),
			"owner":       optComputedString("Owning team or person."),
			"address":     optComputedString("Network address (IP or DNS)."),
			"wg_address":  optComputedString("WireGuard overlay address."),
			"ssh_user":    optComputedString("SSH login user."),
			"ssh_port": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "SSH port.",
			},
			"tags": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "Tags applied to the host.",
			},
			"enrolled": schema.BoolAttribute{
				Computed:            true,
				MarkdownDescription: "Whether the host has completed enrollment.",
			},
		},
	}
}

func (r *hostResource) modelToInput(ctx context.Context, m hostModel, diags *diag.Diagnostics) fleet.HostInput {
	return fleet.HostInput{
		Hostname:    m.Hostname.ValueString(),
		Description: m.Description.ValueString(),
		Environment: m.Environment.ValueString(),
		Owner:       m.Owner.ValueString(),
		Address:     m.Address.ValueString(),
		WGAddress:   m.WGAddress.ValueString(),
		SSHPort:     int(m.SSHPort.ValueInt64()),
		SSHUser:     m.SSHUser.ValueString(),
		Tags:        listToStringSlice(ctx, m.Tags, diags),
	}
}

func (r *hostResource) apply(ctx context.Context, h fleet.Host, m *hostModel, diags *diag.Diagnostics) {
	m.ID = types.StringValue(h.ID)
	m.Hostname = types.StringValue(h.Hostname)
	m.Description = types.StringValue(h.Description)
	m.Environment = types.StringValue(h.Environment)
	m.Owner = types.StringValue(h.Owner)
	m.Address = types.StringValue(h.Address)
	m.WGAddress = types.StringValue(h.WGAddress)
	m.SSHPort = types.Int64Value(int64(h.SSHPort))
	m.SSHUser = types.StringValue(h.SSHUser)
	m.Tags = stringSliceToList(ctx, h.Tags, diags)
	m.Enrolled = types.BoolValue(h.Enrolled)
}

func (r *hostResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan hostModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	h, err := r.client.CreateHost(ctx, r.modelToInput(ctx, plan, &resp.Diagnostics))
	if err != nil {
		resp.Diagnostics.AddError("Could not create host", err.Error())
		return
	}
	r.apply(ctx, h, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *hostResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state hostModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	h, err := r.client.GetHost(ctx, state.ID.ValueString())
	if err != nil {
		if fleet.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Could not read host", err.Error())
		return
	}
	r.apply(ctx, h, &state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *hostResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan hostModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	h, err := r.client.UpdateHost(ctx, plan.ID.ValueString(), r.modelToInput(ctx, plan, &resp.Diagnostics))
	if err != nil {
		resp.Diagnostics.AddError("Could not update host", err.Error())
		return
	}
	r.apply(ctx, h, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *hostResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state hostModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteHost(ctx, state.ID.ValueString()); err != nil && !fleet.IsNotFound(err) {
		resp.Diagnostics.AddError("Could not delete host", err.Error())
	}
}

func (r *hostResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
