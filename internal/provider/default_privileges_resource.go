/*
Copyright 2023 The Cockroach Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package provider

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/jackc/pgx/v5"
)

var _ resource.Resource = &DefaultPrivilegesResource{}

func NewDefaultPrivilegesResource() resource.Resource {
	return &DefaultPrivilegesResource{}
}

type DefaultPrivilegesResource struct {
	client *ccloud.CcloudClient
}

type DefaultPrivilegesResourceModel struct {
	ClusterId  types.String `tfsdk:"cluster_id"`
	Role       types.String `tfsdk:"role_name"`
	Id         types.String `tfsdk:"id"`
	Action     types.String `tfsdk:"action"`
	Privileges types.List   `tfsdk:"privileges"`
	Object     types.String `tfsdk:"object"`
}

func (r *DefaultPrivilegesResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_default_privileges"
}

func (r *DefaultPrivilegesResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Adjust the Default Privileges of a role",
		Attributes: map[string]schema.Attribute{
			"cluster_id": schema.StringAttribute{
				MarkdownDescription: "Cluster ID",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"role_name": schema.StringAttribute{
				MarkdownDescription: "Role",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "ID",
				Computed:            true,
				Required:            false,
				Optional:            false,
			},
			"object": schema.StringAttribute{
				MarkdownDescription: "Object",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"action": schema.StringAttribute{
				MarkdownDescription: "Action",
				Required:            true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"privileges": schema.ListAttribute{
				MarkdownDescription: "privileges",
				Required:            true,
				PlanModifiers: []planmodifier.List{
					listplanmodifier.RequiresReplace(),
				},
			},
		},
	}
}

func (r *DefaultPrivilegesResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*ccloud.CcloudClient)

	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data type", fmt.Sprintf("Expected *CcloudClient, got: %T. Please report this issue to the provider developers.", req.ProviderData))
		return
	}

	r.client = client
}

func getDefaultPrivilegesId(clusterId string, role string, action string, object string) string {
	return "default_privileges|" + clusterId + "|" + role + "|" + action + "|" + object
}

func getDefaultPrivileges(ctx context.Context, tx pgx.Tx) error {
	log.Println("Get the default privileges for this context")
	if _, err := tx.Exec(ctx,
		"SHOW DEFAULT PRIVILEGES FOR {role};"); err != nil {
		return err
	}

	return nil
}

func alterDefaultPrivileges(ctx context.Context, tx pgx.Tx) error {
	log.Println("Alter the default privileges")
	if _, err := tx.Exec(ctx,
		"ALTER DEFAULT PRIVILEGES {action} {privileges - CSV} ON {type} {action_targeting} {role};"); err != nil {
		return err
	}

	return nil
}

func (r *DefaultPrivilegesResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data DefaultPrivilegesResourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	_, err := ccloud.SqlConWithTempUser(ctx, r.client, data.ClusterId.ValueString(), "defaultdb", func(db *pgx.ConnPool) (*interface{}, error) {
		_, err := db.Exec(fmt.Sprintf("GRANT %s TO %s", pgx.Identifier{data.Role.ValueString()}.Sanitize(), pgx.Identifier{data.Username.ValueString()}.Sanitize()))
		return nil, err
	})

	if err != nil {
		resp.Diagnostics.AddError("Failed to grant role", err.Error())
		return
	}

	data.Id = types.StringValue(getDefaultPrivilegesId(data.ClusterId.ValueString(), data.Username.ValueString(), data.Role.ValueString()))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *DefaultPrivilegesResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data DefaultPrivilegesResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	result, err := ccloud.SqlConWithTempUser(ctx, r.client, data.ClusterId.ValueString(), "defaultdb", func(db *pgx.ConnPool) (*bool, error) {
		// If the role is not found, the query will return an empty row
		var result bool
		var response int
		err := db.QueryRow(fmt.Sprintf("select 1 from [show grants on role %s] where member=$1", pgx.Identifier{data.Role.ValueString()}.Sanitize()), data.Username.ValueString()).Scan(&response)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		result = !errors.Is(err, pgx.ErrNoRows)
		return &result, nil
	})

	if err != nil && !errors.Is(err, &ccloud.CockroachCloudClusterNotReadyError{}) && !errors.Is(err, &ccloud.CockroachCloudClusterNotFoundError{}) {
		resp.Diagnostics.AddError("Failed to read role", err.Error())
		return
	}

	if !*result {
		resp.State.RemoveResource(ctx)
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// Update Role grants should never be updated in place, as they are immutable.
// Throw an error if the user tries to do so.
func (r *DefaultPrivilegesResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data DefaultPrivilegesResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	resp.Diagnostics.AddError("Role grants cannot be updated in place", "Role grants cannot be updated in place. Please delete the resource and recreate it.")
}

func (r *DefaultPrivilegesResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data DefaultPrivilegesResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if data.Role.IsNull() || data.Username.IsNull() {
		return
	}

	_, err := ccloud.SqlConWithTempUser(ctx, r.client, data.ClusterId.ValueString(), "defaultdb", func(db *pgx.ConnPool) (*interface{}, error) {
		_, err := db.Exec(fmt.Sprintf("REVOKE %s FROM %s", pgx.Identifier{data.Role.ValueString()}.Sanitize(), pgx.Identifier{data.Username.ValueString()}.Sanitize()))
		return nil, err
	})

	if err != nil {
		resp.Diagnostics.AddError("Failed to revoke role", err.Error())
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
