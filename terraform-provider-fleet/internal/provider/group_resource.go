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

	fleet "github.com/kforbus3/Fleet-Terminal/sdk"
)

var (
	_ resource.Resource                = &groupResource{}
	_ resource.ResourceWithConfigure   = &groupResource{}
	_ resource.ResourceWithImportState = &groupResource{}
)

// NewGroupResource is the fleet_group resource factory.
func NewGroupResource() resource.Resource { return &groupResource{} }

type groupResource struct{ client *fleet.Client }

type groupModel struct {
	ID          types.String    `tfsdk:"id"`
	Name        types.String    `tfsdk:"name"`
	Description types.String    `tfsdk:"description"`
	Rule        *groupRuleModel `tfsdk:"rule"`
}

type groupRuleModel struct {
	Environment      types.String `tfsdk:"environment"`
	TagsAll          types.List   `tfsdk:"tags_all"`
	TagsAny          types.List   `tfsdk:"tags_any"`
	OSContains       types.String `tfsdk:"os_contains"`
	HostnameContains types.String `tfsdk:"hostname_contains"`
}

func (r *groupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (r *groupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *groupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A Fleet group. Add a `rule` block for dynamic (rule-managed) membership; omit it for a manually-managed group.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name":        schema.StringAttribute{Required: true, MarkdownDescription: "Group name."},
			"description": schema.StringAttribute{Optional: true, Computed: true, MarkdownDescription: "Description."},
			"rule": schema.SingleNestedAttribute{
				Optional:            true,
				MarkdownDescription: "Dynamic membership rule. A host matches when every non-empty condition holds.",
				Attributes: map[string]schema.Attribute{
					"environment":       schema.StringAttribute{Optional: true, MarkdownDescription: "Match this environment."},
					"tags_all":          schema.ListAttribute{ElementType: types.StringType, Optional: true, MarkdownDescription: "Host must carry ALL of these tags."},
					"tags_any":          schema.ListAttribute{ElementType: types.StringType, Optional: true, MarkdownDescription: "Host must carry AT LEAST ONE of these tags."},
					"os_contains":       schema.StringAttribute{Optional: true, MarkdownDescription: "OS name contains this substring."},
					"hostname_contains": schema.StringAttribute{Optional: true, MarkdownDescription: "Hostname contains this substring."},
				},
			},
		},
	}
}

func (r *groupResource) modelToInput(ctx context.Context, m groupModel, diags *diag.Diagnostics) fleet.GroupInput {
	in := fleet.GroupInput{Name: m.Name.ValueString(), Description: m.Description.ValueString()}
	if m.Rule != nil {
		in.Rule = &fleet.GroupRule{
			Environment:      m.Rule.Environment.ValueString(),
			TagsAll:          listToStringSlice(ctx, m.Rule.TagsAll, diags),
			TagsAny:          listToStringSlice(ctx, m.Rule.TagsAny, diags),
			OSContains:       m.Rule.OSContains.ValueString(),
			HostnameContains: m.Rule.HostnameContains.ValueString(),
		}
	}
	return in
}

func (r *groupResource) apply(ctx context.Context, g fleet.Group, m *groupModel, diags *diag.Diagnostics) {
	m.ID = types.StringValue(g.ID)
	m.Name = types.StringValue(g.Name)
	m.Description = types.StringValue(g.Description)
	if g.Rule != nil {
		m.Rule = &groupRuleModel{
			Environment:      strOrNull(g.Rule.Environment),
			TagsAll:          listOrNull(ctx, g.Rule.TagsAll, diags),
			TagsAny:          listOrNull(ctx, g.Rule.TagsAny, diags),
			OSContains:       strOrNull(g.Rule.OSContains),
			HostnameContains: strOrNull(g.Rule.HostnameContains),
		}
	} else {
		m.Rule = nil
	}
}

func (r *groupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan groupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	g, err := r.client.CreateGroup(ctx, r.modelToInput(ctx, plan, &resp.Diagnostics))
	if err != nil {
		resp.Diagnostics.AddError("Could not create group", err.Error())
		return
	}
	r.apply(ctx, g, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *groupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state groupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	g, err := r.client.GetGroup(ctx, state.ID.ValueString())
	if err != nil {
		if fleet.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Could not read group", err.Error())
		return
	}
	r.apply(ctx, g, &state, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *groupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan groupModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	g, err := r.client.UpdateGroup(ctx, plan.ID.ValueString(), r.modelToInput(ctx, plan, &resp.Diagnostics))
	if err != nil {
		resp.Diagnostics.AddError("Could not update group", err.Error())
		return
	}
	r.apply(ctx, g, &plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *groupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state groupModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteGroup(ctx, state.ID.ValueString()); err != nil && !fleet.IsNotFound(err) {
		resp.Diagnostics.AddError("Could not delete group", err.Error())
	}
}

func (r *groupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
