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

// ScimGroup struct for ScimGroup.
type ScimGroup struct {
	DisplayName *string         `json:"displayName,omitempty"`
	ExternalId  *string         `json:"externalId,omitempty"`
	Id          *string         `json:"id,omitempty"`
	Members     *[]ScimResource `json:"members,omitempty"`
	Meta        *ScimMetadata   `json:"meta,omitempty"`
	Schemas     *[]string       `json:"schemas,omitempty"`
}

// NewScimGroup instantiates a new ScimGroup object.
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewScimGroup() *ScimGroup {
	p := ScimGroup{}
	return &p
}

// GetDisplayName returns the DisplayName field value if set, zero value otherwise.
func (o *ScimGroup) GetDisplayName() string {
	if o == nil || o.DisplayName == nil {
		var ret string
		return ret
	}
	return *o.DisplayName
}

// SetDisplayName gets a reference to the given string and assigns it to the DisplayName field.
func (o *ScimGroup) SetDisplayName(v string) {
	o.DisplayName = &v
}

// GetExternalId returns the ExternalId field value if set, zero value otherwise.
func (o *ScimGroup) GetExternalId() string {
	if o == nil || o.ExternalId == nil {
		var ret string
		return ret
	}
	return *o.ExternalId
}

// SetExternalId gets a reference to the given string and assigns it to the ExternalId field.
func (o *ScimGroup) SetExternalId(v string) {
	o.ExternalId = &v
}

// GetId returns the Id field value if set, zero value otherwise.
func (o *ScimGroup) GetId() string {
	if o == nil || o.Id == nil {
		var ret string
		return ret
	}
	return *o.Id
}

// SetId gets a reference to the given string and assigns it to the Id field.
func (o *ScimGroup) SetId(v string) {
	o.Id = &v
}

// GetMembers returns the Members field value if set, zero value otherwise.
func (o *ScimGroup) GetMembers() []ScimResource {
	if o == nil || o.Members == nil {
		var ret []ScimResource
		return ret
	}
	return *o.Members
}

// SetMembers gets a reference to the given []ScimResource and assigns it to the Members field.
func (o *ScimGroup) SetMembers(v []ScimResource) {
	o.Members = &v
}

// GetMeta returns the Meta field value if set, zero value otherwise.
func (o *ScimGroup) GetMeta() ScimMetadata {
	if o == nil || o.Meta == nil {
		var ret ScimMetadata
		return ret
	}
	return *o.Meta
}

// SetMeta gets a reference to the given ScimMetadata and assigns it to the Meta field.
func (o *ScimGroup) SetMeta(v ScimMetadata) {
	o.Meta = &v
}

// GetSchemas returns the Schemas field value if set, zero value otherwise.
func (o *ScimGroup) GetSchemas() []string {
	if o == nil || o.Schemas == nil {
		var ret []string
		return ret
	}
	return *o.Schemas
}

// SetSchemas gets a reference to the given []string and assigns it to the Schemas field.
func (o *ScimGroup) SetSchemas(v []string) {
	o.Schemas = &v
}