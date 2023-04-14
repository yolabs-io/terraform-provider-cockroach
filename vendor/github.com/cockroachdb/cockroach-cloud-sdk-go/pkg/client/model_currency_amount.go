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

// CurrencyAmount struct for CurrencyAmount.
type CurrencyAmount struct {
	// amount is the quantity of currency. Internally, currency amounts are tracked and stored using an arbitrary-precision decimal representation, but are serialized as 64-bit floating point numbers. There may be minor rounding discrepancies when parsed as a 32-bit float.
	Amount   *float64      `json:"amount,omitempty"`
	Currency *CurrencyType `json:"currency,omitempty"`
}

// NewCurrencyAmount instantiates a new CurrencyAmount object.
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewCurrencyAmount() *CurrencyAmount {
	p := CurrencyAmount{}
	return &p
}

// GetAmount returns the Amount field value if set, zero value otherwise.
func (o *CurrencyAmount) GetAmount() float64 {
	if o == nil || o.Amount == nil {
		var ret float64
		return ret
	}
	return *o.Amount
}

// SetAmount gets a reference to the given float64 and assigns it to the Amount field.
func (o *CurrencyAmount) SetAmount(v float64) {
	o.Amount = &v
}

// GetCurrency returns the Currency field value if set, zero value otherwise.
func (o *CurrencyAmount) GetCurrency() CurrencyType {
	if o == nil || o.Currency == nil {
		var ret CurrencyType
		return ret
	}
	return *o.Currency
}

// SetCurrency gets a reference to the given CurrencyType and assigns it to the Currency field.
func (o *CurrencyAmount) SetCurrency(v CurrencyType) {
	o.Currency = &v
}

func (o CurrencyAmount) MarshalJSON() ([]byte, error) {
	toSerialize := map[string]interface{}{}
	if o.Amount != nil {
		toSerialize["amount"] = o.Amount
	}
	if o.Currency != nil {
		toSerialize["currency"] = o.Currency
	}
	return json.Marshal(toSerialize)
}