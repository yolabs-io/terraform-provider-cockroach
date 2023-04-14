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
// API version: 2023-04-10

package client

import (
	"encoding/json"
)

// ServerlessClusterCreateSpecification struct for ServerlessClusterCreateSpecification.
type ServerlessClusterCreateSpecification struct {
	// Preview: Specify which region should be made the primary region. This is only applicable to multi-region Serverless clusters. This field is required if you create the cluster in more than one region.
	PrimaryRegion *string `json:"primary_region,omitempty"`
	// Region values should match the cloud provider's zone code. For example, for Oregon, set region_name to \"us-west2\" for GCP and \"us-west-2\" for AWS.
	Regions []string `json:"regions"`
	// spend_limit is the maximum monthly charge for a cluster, in US cents. We recommend using usage_limits instead, since spend_limit will be deprecated in the future.
	SpendLimit  *int32       `json:"spend_limit,omitempty"`
	UsageLimits *UsageLimits `json:"usage_limits,omitempty"`
}

// NewServerlessClusterCreateSpecification instantiates a new ServerlessClusterCreateSpecification object.
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewServerlessClusterCreateSpecification(regions []string) *ServerlessClusterCreateSpecification {
	p := ServerlessClusterCreateSpecification{}
	p.Regions = regions
	return &p
}

// NewServerlessClusterCreateSpecificationWithDefaults instantiates a new ServerlessClusterCreateSpecification object.
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewServerlessClusterCreateSpecificationWithDefaults() *ServerlessClusterCreateSpecification {
	p := ServerlessClusterCreateSpecification{}
	return &p
}

// GetPrimaryRegion returns the PrimaryRegion field value if set, zero value otherwise.
func (o *ServerlessClusterCreateSpecification) GetPrimaryRegion() string {
	if o == nil || o.PrimaryRegion == nil {
		var ret string
		return ret
	}
	return *o.PrimaryRegion
}

// SetPrimaryRegion gets a reference to the given string and assigns it to the PrimaryRegion field.
func (o *ServerlessClusterCreateSpecification) SetPrimaryRegion(v string) {
	o.PrimaryRegion = &v
}

// GetRegions returns the Regions field value.
func (o *ServerlessClusterCreateSpecification) GetRegions() []string {
	if o == nil {
		var ret []string
		return ret
	}

	return o.Regions
}

// SetRegions sets field value.
func (o *ServerlessClusterCreateSpecification) SetRegions(v []string) {
	o.Regions = v
}

// GetSpendLimit returns the SpendLimit field value if set, zero value otherwise.
func (o *ServerlessClusterCreateSpecification) GetSpendLimit() int32 {
	if o == nil || o.SpendLimit == nil {
		var ret int32
		return ret
	}
	return *o.SpendLimit
}

// SetSpendLimit gets a reference to the given int32 and assigns it to the SpendLimit field.
func (o *ServerlessClusterCreateSpecification) SetSpendLimit(v int32) {
	o.SpendLimit = &v
}

// GetUsageLimits returns the UsageLimits field value if set, zero value otherwise.
func (o *ServerlessClusterCreateSpecification) GetUsageLimits() UsageLimits {
	if o == nil || o.UsageLimits == nil {
		var ret UsageLimits
		return ret
	}
	return *o.UsageLimits
}

// SetUsageLimits gets a reference to the given UsageLimits and assigns it to the UsageLimits field.
func (o *ServerlessClusterCreateSpecification) SetUsageLimits(v UsageLimits) {
	o.UsageLimits = &v
}

func (o ServerlessClusterCreateSpecification) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.PrimaryRegion != nil {
		toSerialize["primary_region"] = o.PrimaryRegion
	}
	if true {
		toSerialize["regions"] = o.Regions
	}
	if o.SpendLimit != nil {
		toSerialize["spend_limit"] = o.SpendLimit
	}
	if o.UsageLimits != nil {
		toSerialize["usage_limits"] = o.UsageLimits
	}
	return json.Marshal(toSerialize)
}