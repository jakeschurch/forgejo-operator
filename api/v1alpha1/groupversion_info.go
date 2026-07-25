// Package v1alpha1 contains the Forgejo operator API.
// +kubebuilder:object:generate=true
// +groupName=forgejo.jakeschurch.com
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var GroupVersion = schema.GroupVersion{Group: "forgejo.jakeschurch.com", Version: "v1alpha1"}
var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}
var AddToScheme = SchemeBuilder.AddToScheme
