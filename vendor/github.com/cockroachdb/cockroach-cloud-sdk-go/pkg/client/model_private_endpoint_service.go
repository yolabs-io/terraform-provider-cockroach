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

// PrivateEndpointService struct for PrivateEndpointService.
type PrivateEndpointService struct {
	// availability_zone_ids are the unique identifiers for the availability zones in which this service is available. Note these identifiers are unique even across typical cloud provider boundaries, for example AWS accounts or organizations. In AWS, availability zone ids for us-east-1 are use1-az1, use1-az2, use1-az3.
	AvailabilityZoneIds []string                     `json:"availability_zone_ids"`
	Aws                 *AWSPrivateLinkServiceDetail `json:"aws,omitempty"`
	CloudProvider       CloudProviderType            `json:"cloud_provider"`
	// endpoint_service_id uniquely identifies this private endpoint service. This is the cloud provider generated id for the service.
	EndpointServiceId string `json:"endpoint_service_id"`
	// name is the name of the private endpoints service.
	Name string `json:"name"`
	// region_name is the cloud provider region name (e.g. us-east-1).
	RegionName string                           `json:"region_name"`
	Status     PrivateEndpointServiceStatusType `json:"status"`
}

// NewPrivateEndpointService instantiates a new PrivateEndpointService object.
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewPrivateEndpointService(availabilityZoneIds []string, cloudProvider CloudProviderType, endpointServiceId string, name string, regionName string, status PrivateEndpointServiceStatusType) *PrivateEndpointService {
	p := PrivateEndpointService{}
	p.AvailabilityZoneIds = availabilityZoneIds
	p.CloudProvider = cloudProvider
	p.EndpointServiceId = endpointServiceId
	p.Name = name
	p.RegionName = regionName
	p.Status = status
	return &p
}

// NewPrivateEndpointServiceWithDefaults instantiates a new PrivateEndpointService object.
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewPrivateEndpointServiceWithDefaults() *PrivateEndpointService {
	p := PrivateEndpointService{}
	return &p
}

// GetAvailabilityZoneIds returns the AvailabilityZoneIds field value.
func (o *PrivateEndpointService) GetAvailabilityZoneIds() []string {
	if o == nil {
		var ret []string
		return ret
	}

	return o.AvailabilityZoneIds
}

// SetAvailabilityZoneIds sets field value.
func (o *PrivateEndpointService) SetAvailabilityZoneIds(v []string) {
	o.AvailabilityZoneIds = v
}

// GetAws returns the Aws field value if set, zero value otherwise.
func (o *PrivateEndpointService) GetAws() AWSPrivateLinkServiceDetail {
	if o == nil || o.Aws == nil {
		var ret AWSPrivateLinkServiceDetail
		return ret
	}
	return *o.Aws
}

// SetAws gets a reference to the given AWSPrivateLinkServiceDetail and assigns it to the Aws field.
func (o *PrivateEndpointService) SetAws(v AWSPrivateLinkServiceDetail) {
	o.Aws = &v
}

// GetCloudProvider returns the CloudProvider field value.
func (o *PrivateEndpointService) GetCloudProvider() CloudProviderType {
	if o == nil {
		var ret CloudProviderType
		return ret
	}

	return o.CloudProvider
}

// SetCloudProvider sets field value.
func (o *PrivateEndpointService) SetCloudProvider(v CloudProviderType) {
	o.CloudProvider = v
}

// GetEndpointServiceId returns the EndpointServiceId field value.
func (o *PrivateEndpointService) GetEndpointServiceId() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.EndpointServiceId
}

// SetEndpointServiceId sets field value.
func (o *PrivateEndpointService) SetEndpointServiceId(v string) {
	o.EndpointServiceId = v
}

// GetName returns the Name field value.
func (o *PrivateEndpointService) GetName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.Name
}

// SetName sets field value.
func (o *PrivateEndpointService) SetName(v string) {
	o.Name = v
}

// GetRegionName returns the RegionName field value.
func (o *PrivateEndpointService) GetRegionName() string {
	if o == nil {
		var ret string
		return ret
	}

	return o.RegionName
}

// SetRegionName sets field value.
func (o *PrivateEndpointService) SetRegionName(v string) {
	o.RegionName = v
}

// GetStatus returns the Status field value.
func (o *PrivateEndpointService) GetStatus() PrivateEndpointServiceStatusType {
	if o == nil {
		var ret PrivateEndpointServiceStatusType
		return ret
	}

	return o.Status
}

// SetStatus sets field value.
func (o *PrivateEndpointService) SetStatus(v PrivateEndpointServiceStatusType) {
	o.Status = v
}
