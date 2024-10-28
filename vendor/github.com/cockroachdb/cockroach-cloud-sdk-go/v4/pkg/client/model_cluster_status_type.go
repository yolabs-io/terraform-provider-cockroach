// Copyright 2023 The Cockroach Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.
// CockroachDB Cloud API
// API version: 2024-09-16

package client

import (
	"fmt"
)

// ClusterStatusType the model 'ClusterStatusType'.
type ClusterStatusType string

// List of ClusterStatus.Type.
const (
	CLUSTERSTATUSTYPE_UNSPECIFIED                            ClusterStatusType = "UNSPECIFIED"
	CLUSTERSTATUSTYPE_CRDB_MAJOR_UPGRADE_RUNNING             ClusterStatusType = "CRDB_MAJOR_UPGRADE_RUNNING"
	CLUSTERSTATUSTYPE_CRDB_MAJOR_UPGRADE_FAILED              ClusterStatusType = "CRDB_MAJOR_UPGRADE_FAILED"
	CLUSTERSTATUSTYPE_CRDB_MAJOR_ROLLBACK_RUNNING            ClusterStatusType = "CRDB_MAJOR_ROLLBACK_RUNNING"
	CLUSTERSTATUSTYPE_CRDB_MAJOR_ROLLBACK_FAILED             ClusterStatusType = "CRDB_MAJOR_ROLLBACK_FAILED"
	CLUSTERSTATUSTYPE_CRDB_PATCH_RUNNING                     ClusterStatusType = "CRDB_PATCH_RUNNING"
	CLUSTERSTATUSTYPE_CRDB_PATCH_FAILED                      ClusterStatusType = "CRDB_PATCH_FAILED"
	CLUSTERSTATUSTYPE_CRDB_SCALE_RUNNING                     ClusterStatusType = "CRDB_SCALE_RUNNING"
	CLUSTERSTATUSTYPE_CRDB_SCALE_FAILED                      ClusterStatusType = "CRDB_SCALE_FAILED"
	CLUSTERSTATUSTYPE_MAINTENANCE_RUNNING                    ClusterStatusType = "MAINTENANCE_RUNNING"
	CLUSTERSTATUSTYPE_CRDB_INSTANCE_UPDATE_RUNNING           ClusterStatusType = "CRDB_INSTANCE_UPDATE_RUNNING"
	CLUSTERSTATUSTYPE_CRDB_INSTANCE_UPDATE_FAILED            ClusterStatusType = "CRDB_INSTANCE_UPDATE_FAILED"
	CLUSTERSTATUSTYPE_CRDB_EDIT_CLUSTER_RUNNING              ClusterStatusType = "CRDB_EDIT_CLUSTER_RUNNING"
	CLUSTERSTATUSTYPE_CRDB_EDIT_CLUSTER_FAILED               ClusterStatusType = "CRDB_EDIT_CLUSTER_FAILED"
	CLUSTERSTATUSTYPE_CRDB_CMEK_OPERATION_RUNNING            ClusterStatusType = "CRDB_CMEK_OPERATION_RUNNING"
	CLUSTERSTATUSTYPE_CRDB_CMEK_OPERATION_FAILED             ClusterStatusType = "CRDB_CMEK_OPERATION_FAILED"
	CLUSTERSTATUSTYPE_TENANT_RESTORE_RUNNING                 ClusterStatusType = "TENANT_RESTORE_RUNNING"
	CLUSTERSTATUSTYPE_TENANT_RESTORE_FAILED                  ClusterStatusType = "TENANT_RESTORE_FAILED"
	CLUSTERSTATUSTYPE_CRDB_LOG_EXPORT_OPERATION_RUNNING      ClusterStatusType = "CRDB_LOG_EXPORT_OPERATION_RUNNING"
	CLUSTERSTATUSTYPE_CRDB_LOG_EXPORT_OPERATION_FAILED       ClusterStatusType = "CRDB_LOG_EXPORT_OPERATION_FAILED"
	CLUSTERSTATUSTYPE_CRDB_CLUSTER_DISRUPTION_RUNNING        ClusterStatusType = "CRDB_CLUSTER_DISRUPTION_RUNNING"
	CLUSTERSTATUSTYPE_CRDB_CLUSTER_DISRUPTION_FAILED         ClusterStatusType = "CRDB_CLUSTER_DISRUPTION_FAILED"
	CLUSTERSTATUSTYPE_CRDB_REPAVE_RUNNING                    ClusterStatusType = "CRDB_REPAVE_RUNNING"
	CLUSTERSTATUSTYPE_CRDB_REPAVE_FAILED                     ClusterStatusType = "CRDB_REPAVE_FAILED"
	CLUSTERSTATUSTYPE_CRDB_CUSTOM_CLIENT_CA_RUNNING          ClusterStatusType = "CRDB_CUSTOM_CLIENT_CA_RUNNING"
	CLUSTERSTATUSTYPE_CRDB_CUSTOM_CLIENT_CA_FAILED           ClusterStatusType = "CRDB_CUSTOM_CLIENT_CA_FAILED"
	CLUSTERSTATUSTYPE_DEDICATED_FULL_CLUSTER_RESTORE_RUNNING ClusterStatusType = "DEDICATED_FULL_CLUSTER_RESTORE_RUNNING"
	CLUSTERSTATUSTYPE_DEDICATED_FULL_CLUSTER_RESTORE_FAILED  ClusterStatusType = "DEDICATED_FULL_CLUSTER_RESTORE_FAILED"
)

// All allowed values of ClusterStatusType enum.
var AllowedClusterStatusTypeEnumValues = []ClusterStatusType{
	"UNSPECIFIED",
	"CRDB_MAJOR_UPGRADE_RUNNING",
	"CRDB_MAJOR_UPGRADE_FAILED",
	"CRDB_MAJOR_ROLLBACK_RUNNING",
	"CRDB_MAJOR_ROLLBACK_FAILED",
	"CRDB_PATCH_RUNNING",
	"CRDB_PATCH_FAILED",
	"CRDB_SCALE_RUNNING",
	"CRDB_SCALE_FAILED",
	"MAINTENANCE_RUNNING",
	"CRDB_INSTANCE_UPDATE_RUNNING",
	"CRDB_INSTANCE_UPDATE_FAILED",
	"CRDB_EDIT_CLUSTER_RUNNING",
	"CRDB_EDIT_CLUSTER_FAILED",
	"CRDB_CMEK_OPERATION_RUNNING",
	"CRDB_CMEK_OPERATION_FAILED",
	"TENANT_RESTORE_RUNNING",
	"TENANT_RESTORE_FAILED",
	"CRDB_LOG_EXPORT_OPERATION_RUNNING",
	"CRDB_LOG_EXPORT_OPERATION_FAILED",
	"CRDB_CLUSTER_DISRUPTION_RUNNING",
	"CRDB_CLUSTER_DISRUPTION_FAILED",
	"CRDB_REPAVE_RUNNING",
	"CRDB_REPAVE_FAILED",
	"CRDB_CUSTOM_CLIENT_CA_RUNNING",
	"CRDB_CUSTOM_CLIENT_CA_FAILED",
	"DEDICATED_FULL_CLUSTER_RESTORE_RUNNING",
	"DEDICATED_FULL_CLUSTER_RESTORE_FAILED",
}

// NewClusterStatusTypeFromValue returns a pointer to a valid ClusterStatusType
// for the value passed as argument, or an error if the value passed is not allowed by the enum.
func NewClusterStatusTypeFromValue(v string) (*ClusterStatusType, error) {
	ev := ClusterStatusType(v)
	if ev.IsValid() {
		return &ev, nil
	} else {
		return nil, fmt.Errorf("invalid value '%v' for ClusterStatusType: valid values are %v", v, AllowedClusterStatusTypeEnumValues)
	}
}

// IsValid return true if the value is valid for the enum, false otherwise.
func (v ClusterStatusType) IsValid() bool {
	for _, existing := range AllowedClusterStatusTypeEnumValues {
		if existing == v {
			return true
		}
	}
	return false
}

// Ptr returns reference to ClusterStatus.Type value.
func (v ClusterStatusType) Ptr() *ClusterStatusType {
	return &v
}