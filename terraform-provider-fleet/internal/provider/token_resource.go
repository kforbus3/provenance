package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	fleet "github.com/kforbus3/Fleet-Terminal/sdk"
)

var (
	_ resource.Resource              = &serviceAccountTokenResource{}
	_ resource.ResourceWithConfigure = &serviceAccountTokenResource{}
)

// NewServiceAccountTokenResource is the fleet_service_account_token resource factory.
func NewServiceAccountTokenResource() resource.Resource { return &serviceAccountTokenResource{} }

type serviceAccountTokenResource struct{ client *fleet.Client }

type tokenModel struct {
	ID               types.String `tfsdk:"id"`
	ServiceAccountID types.String `tfsdk:"service_account_id"`
	Name             types.String `tfsdk:"name"`
	ExpiresInDays    types.Int64  `tfsdk:"expires_in_days"`
	Token            types.String `tfsdk:"token"`
}

func (r *serviceAccountTokenResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_account_token"
}

func (r *serviceAccountTokenResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *serviceAccountTokenResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An API token for a service account. The secret is returned only once, at creation, and stored (sensitive) in Terraform state. Any change replaces the token.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"service_account_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The service account this token belongs to.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Token name.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"expires_in_days": schema.Int64Attribute{
				Optional:            true,
				MarkdownDescription: "Days until the token expires (omit for no expiry).",
				PlanModifiers:       []planmodifier.Int64{int64planmodifier.RequiresReplace()},
			},
			"token": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "The token secret (shown once). Store it securely.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *serviceAccountTokenResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan tokenModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tok, err := r.client.CreateToken(ctx, plan.ServiceAccountID.ValueString(), fleet.TokenInput{
		Name:          plan.Name.ValueString(),
		ExpiresInDays: int(plan.ExpiresInDays.ValueInt64()),
	})
	if err != nil {
		resp.Diagnostics.AddError("Could not create token", err.Error())
		return
	}
	plan.ID = types.StringValue(tok.ID)
	plan.Name = types.StringValue(tok.Name)
	plan.Token = types.StringValue(tok.Secret)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceAccountTokenResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state tokenModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	toks, err := r.client.ListTokens(ctx, state.ServiceAccountID.ValueString())
	if err != nil {
		if fleet.IsNotFound(err) { // the service account itself is gone
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Could not read token", err.Error())
		return
	}
	for _, t := range toks {
		if t.ID == state.ID.ValueString() {
			if t.RevokedAt != nil {
				resp.State.RemoveResource(ctx) // revoked out of band
				return
			}
			state.Name = types.StringValue(t.Name)
			// token secret is never returned again — keep it from state.
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			return
		}
	}
	resp.State.RemoveResource(ctx) // no longer present
}

// Update is unreachable — every attribute forces replacement.
func (r *serviceAccountTokenResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan tokenModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceAccountTokenResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state tokenModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.RevokeToken(ctx, state.ServiceAccountID.ValueString(), state.ID.ValueString()); err != nil && !fleet.IsNotFound(err) {
		resp.Diagnostics.AddError("Could not revoke token", err.Error())
	}
}
