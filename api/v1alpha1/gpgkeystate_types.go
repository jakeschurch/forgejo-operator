package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// GPGKeyStateSpec is operator-only provenance and lifecycle state. Never grant
// tenants, reflectors or aggregated user roles write access to this resource.
type GPGKeyStateSpec struct {
	Minted            map[string]string  `json:"minted"`
	CurrentID         string             `json:"currentID,omitempty"`
	PendingID         string             `json:"pendingID,omitempty"`
	CreatedAt         metav1.Time        `json:"createdAt,omitempty"`
	Retiring          []GPGKeyRetirement `json:"retiring,omitempty"`
	UnauthorizedSince *metav1.Time       `json:"unauthorizedSince,omitempty"`
}

type GPGKeyRetirement struct {
	KeyID       string      `json:"keyID"`
	RemoveAfter metav1.Time `json:"removeAfter"`
}

// ForgejoGPGKeyState is a cluster-scoped trust root. A namespaced CR cannot
// legally own a cluster-scoped object, so source coordinates and UID are bound
// by annotations and checked on every read. Records are retained for audit.
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
type ForgejoGPGKeyState struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              GPGKeyStateSpec `json:"spec"`
}

// +kubebuilder:object:root=true
type ForgejoGPGKeyStateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoGPGKeyState `json:"items"`
}

func init() { SchemeBuilder.Register(&ForgejoGPGKeyState{}, &ForgejoGPGKeyStateList{}) }
