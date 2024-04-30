/*
Copyright 2023.

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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// ApiGwSpec defines the desired state of ApiGw
type ApiGwSpec struct {
	Host    string `json:"host,omitempty"`
	Path    string `json:"path,omitempty"`
	Service string `json:"service,omitempty"`
	Port    int32  `json:"port,omitempty"`
	Auth    Auth   `json:"auth,omitempty"`
}

type Auth struct {
	// Valid types: none, basic
	Type  string    `json:"type,omitempty"`
	Basic BasicAuth `json:"basic,omitempty"`
}

type BasicAuth struct {
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
}

// ApiGwStatus defines the observed state of ApiGw
type ApiGwStatus struct {
	// +operator-sdk:csv:customresourcedefinitions:type=status
	State string `json:"state,omitempty" patchStrategy:"merge"`
	Hash  string `json:"hash,omitempty" patchStrategy:"merge"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// ApiGw is the Schema for the apigws API
type ApiGw struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ApiGwSpec   `json:"spec,omitempty"`
	Status ApiGwStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// ApiGwList contains a list of ApiGw
type ApiGwList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ApiGw `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ApiGw{}, &ApiGwList{})
}
