package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	fleet "github.com/your-org/Fleet-Terminal/sdk"
)

var (
	_ resource.Resource                = &serviceAccountResource{}
	_ resource.ResourceWithConfigure   = &serviceAccountResource{}
	_ resource.ResourceWithImportState = &serviceAccountResource{}
)

// NewServiceAccountResource is the fleet_service_account resource factory.
func NewServiceAccountResource() resource.Resource { return &serviceAccountResource{} }

type serviceAccountResource struct{ client *fleet.Client }

type serviceAccountModel struct {
	ID          types.String `tfsdk:"id"`
	Username    types.String `tfsdk:"username"`
	DisplayName types.String `tfsdk:"display_name"`
	RoleIDs     types.List   `tfsdk:"role_ids"`
	GroupIDs    types.List   `tfsdk:"group_ids"`
}

func (r *serviceAccountResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_account"
}

func (r *serviceAccountResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *serviceAccountResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	// The API has no update for service accounts, so every configurable attribute
	// forces replacement.
	resp.Schema = schema.Schema{
		MarkdownDescription: "A Fleet service account (non-interactive identity for automation). Changing any attribute replaces the account, because the API does not support in-place updates. Use `fleet_service_account_token` to issue its API tokens.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"username": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Service-account username.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"display_name": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Display name.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"role_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Role UUIDs to grant (see the fleet_role data source).",
				PlanModifiers:       []planmodifier.List{listplanmodifier.RequiresReplace()},
			},
			"group_ids": schema.ListAttribute{
				ElementType:         types.StringType,
				Optional:            true,
				MarkdownDescription: "Group UUIDs to grant.",
				PlanModifiers:       []planmodifier.List{listplanmodifier.RequiresReplace()},
			},
		},
	}
}

func (r *serviceAccountResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan serviceAccountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	sa, err := r.client.CreateServiceAccount(ctx, fleet.ServiceAccountInput{
		Username:    plan.Username.ValueString(),
		DisplayName: plan.DisplayName.ValueString(),
		RoleIDs:     listToStringSlice(ctx, plan.RoleIDs, &resp.Diagnostics),
		GroupIDs:    listToStringSlice(ctx, plan.GroupIDs, &resp.Diagnostics),
	})
	if err != nil {
		resp.Diagnostics.AddError("Could not create service account", err.Error())
		return
	}
	plan.ID = types.StringValue(sa.ID)
	plan.Username = types.StringValue(sa.Username)
	plan.DisplayName = strOrNull(sa.DisplayName)
	// role_ids/group_ids are preserved from the plan: the API returns role/group
	// NAMES, not the IDs the config uses, so we cannot round-trip them.
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceAccountResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state serviceAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	sa, err := r.client.GetServiceAccount(ctx, state.ID.ValueString())
	if err != nil {
		if fleet.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Could not read service account", err.Error())
		return
	}
	state.Username = types.StringValue(sa.Username)
	state.DisplayName = strOrNull(sa.DisplayName)
	// role_ids/group_ids left as-is (see Create).
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is unreachable in practice — every attribute forces replacement — but the
// interface requires it. Persist the plan defensively.
func (r *serviceAccountResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan serviceAccountModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceAccountResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state serviceAccountModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteServiceAccount(ctx, state.ID.ValueString()); err != nil && !fleet.IsNotFound(err) {
		resp.Diagnostics.AddError("Could not delete service account", err.Error())
	}
}

func (r *serviceAccountResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
