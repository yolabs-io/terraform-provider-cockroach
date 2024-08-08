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

// ScimEmail struct for ScimEmail.
type ScimEmail struct {
	Display *string `json:"display,omitempty"`
	Primary bool    `json:"primary"`
	Type    *string `json:"type,omitempty"`
	Value   string  `json:"value"`
}

// NewScimEmail instantiates a new ScimEmail object.
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewScimEmail(primary bool, value string) *ScimEmail {
	p := ScimEmail{}
	p.Primary = primary
	p.Value = value
	return &p
}

// NewScimEmailWithDefaults instantiates a new ScimEmail object.
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewScimEmailWithDefaults() *ScimEmail {
	p := ScimEmail{}
	return &p
}

// GetDisplay returns the Display field value if set, zero value otherwise.
func (o *ScimEmail) GetDisplay() string {
	if o == nil || o.Display == nil {
		var ret string
		return ret
	}
	return *o.Display
}

// SetDisplay gets a reference to the given string and assigns it to the Display field.
func (o *ScimEmail) SetDisplay(v string) {
	o.Display = &v
}

// GetPrimary returns the Primary field value.
func (o *ScimEmail) GetPrimary() bool {
	if o == nil {
		var ret bool
		return ret
	}

	return o.Primary
}

// SetPrimary sets field value.
func (o *ScimEmail) SetPrimary(v bool) {
	o.Primary = v
}

// GetType returns the Type field value if set, zero value otherwise.
func (o *ScimEmail) GetType() string {
	if o == nil || o.Type == nil {
		var ret string
		return ret
	}
	return *o.Type
}

// SetType gets a reference to the given string and assigns it to the Type field.
func (o *ScimEmail) SetType(v string) {
	o.Type = &v
}

// GetValue returns the Value field value.
func (o *ScimEmail) GetValue() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Value
}

// SetValue sets field value.
func (o *ScimEmail) SetValue(v string) {
	o.Value = v
}