package provider

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	prov "github.com/kforbus3/provenance/sdk"
)

var (
	_ resource.Resource                = &networkRangeResource{}
	_ resource.ResourceWithConfigure   = &networkRangeResource{}
	_ resource.ResourceWithImportState = &networkRangeResource{}
)

// NewNetworkRangeResource is the prov_network_range resource factory.
func NewNetworkRangeResource() resource.Resource { return &networkRangeResource{} }

type networkRangeResource struct{ client *prov.Client }

type networkRangeModel struct {
	ID      types.String `tfsdk:"id"`
	Name    types.String `tfsdk:"name"`
	CIDR    types.String `tfsdk:"cidr"`
	Note    types.String `tfsdk:"note"`
	Enabled types.Bool   `tfsdk:"enabled"`
}

func (r *networkRangeResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_network_range"
}

func (r *networkRangeResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *networkRangeResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A network range the network scanner sweeps for devices that are not managed hosts " +
			"(switches, printers, appliances). Live addresses are found with the common ports, then each is " +
			"scanned in full. Requires System.Configure.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{Required: true, MarkdownDescription: "Display name."},
			"cidr": schema.StringAttribute{
				Required: true,
				MarkdownDescription: "The network in canonical CIDR form, e.g. `10.0.2.0/24` (not `10.0.2.5/24`). " +
					"At most 1024 addresses; loopback, link-local and multicast are refused.",
				Validators: []validator.String{canonicalCIDR{}},
			},
			"note": schema.StringAttribute{
				Optional: true, Computed: true, Default: stringdefault.StaticString(""),
				MarkdownDescription: "Free-text note.",
			},
			"enabled": schema.BoolAttribute{
				Optional: true, Computed: true, Default: booldefault.StaticBool(true),
				MarkdownDescription: "Included in scheduled range scans. Default true.",
			},
		},
	}
}

// canonicalCIDR refuses a CIDR the API would store differently. The API masks
// host bits away, so 10.0.2.5/24 would come back as 10.0.2.0/24 and Terraform would
// report an inconsistent result after apply; saying so at plan time is kinder.
type canonicalCIDR struct{}

func (canonicalCIDR) Description(context.Context) string {
	return "must be a canonical CIDR (network address, no host bits)"
}
func (v canonicalCIDR) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (canonicalCIDR) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	raw := strings.TrimSpace(req.ConfigValue.ValueString())
	p, err := netip.ParsePrefix(raw)
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid CIDR",
			fmt.Sprintf("%q is not CIDR notation (e.g. 10.0.2.0/24; a single address is 10.0.2.40/32).", raw))
		return
	}
	if m := p.Masked(); m.String() != raw {
		resp.Diagnostics.AddAttributeError(req.Path, "CIDR has host bits set",
			fmt.Sprintf("Use %s: the API stores the network address, so %s would change after apply.", m, raw))
	}
}

func (r *networkRangeResource) input(m networkRangeModel) prov.NetScanRangeInput {
	enabled := m.Enabled.ValueBool()
	return prov.NetScanRangeInput{Name: m.Name.ValueString(), CIDR: m.CIDR.ValueString(),
		Note: m.Note.ValueString(), Enabled: &enabled}
}

func applyRange(rg prov.NetScanRange, m *networkRangeModel) {
	m.ID = types.StringValue(rg.ID)
	m.Name = types.StringValue(rg.Name)
	m.CIDR = types.StringValue(rg.CIDR)
	m.Note = types.StringValue(rg.Note)
	m.Enabled = types.BoolValue(rg.Enabled)
}

func (r *networkRangeResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan networkRangeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	rg, err := r.client.CreateNetScanRange(ctx, r.input(plan))
	if err != nil {
		resp.Diagnostics.AddError("Could not create network range", err.Error())
		return
	}
	applyRange(rg, &plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *networkRangeResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state networkRangeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	rg, err := r.client.GetNetScanRange(ctx, state.ID.ValueString())
	if err != nil {
		if prov.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("Could not read network range", err.Error())
		return
	}
	applyRange(rg, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *networkRangeResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan networkRangeModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	rg, err := r.client.UpdateNetScanRange(ctx, plan.ID.ValueString(), r.input(plan))
	if err != nil {
		resp.Diagnostics.AddError("Could not update network range", err.Error())
		return
	}
	applyRange(rg, &plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *networkRangeResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state networkRangeModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.DeleteNetScanRange(ctx, state.ID.ValueString()); err != nil && !prov.IsNotFound(err) {
		resp.Diagnostics.AddError("Could not delete network range", err.Error())
	}
}

func (r *networkRangeResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
