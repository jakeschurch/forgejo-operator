package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// SSHKeySpec declares an existing user's SSH public key, typically the key the
// user signs commits with (git config gpg.format=ssh). The operator never holds
// the private key: it registers the public half and reports whether the owner
// has proven possession, which Forgejo requires before it trusts signatures.
// Forgejo has no signing-only key type: a registered key also authenticates
// git-over-SSH as the user.
// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.user == oldSelf.user && self.publicKey == oldSelf.publicKey",message="providerRef, user and publicKey are immutable"
// +kubebuilder:validation:XValidation:rule="has(self.providerNamespace) == has(oldSelf.providerNamespace) && (!has(self.providerNamespace) || self.providerNamespace == oldSelf.providerNamespace)",message="providerNamespace is immutable"
type SSHKeySpec struct {
	// +kubebuilder:validation:MinLength=1
	ProviderRef string `json:"providerRef"`
	// +optional
	ProviderNamespace string `json:"providerNamespace,omitempty"`
	// +kubebuilder:validation:MinLength=1
	User string `json:"user"`
	// Title is used only when the operator creates the key. A key already on the
	// account (matched by fingerprint) is adopted with its existing title:
	// Forgejo cannot rename keys, and recreating one discards its verification.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=50
	Title string `json:"title"`
	// PublicKey is one authorized_keys line: "<type> <base64> [comment]".
	// +kubebuilder:validation:MinLength=1
	PublicKey string `json:"publicKey"`
	// Orphan leaves the key (and its verification) on the account on deletion.
	// +kubebuilder:default=Orphan
	// +kubebuilder:validation:Enum=Orphan;Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
}

type SSHKeyStatus struct {
	CommonStatus `json:",inline"`
	// Fingerprint is the SHA256 fingerprint Forgejo matches signatures against.
	Fingerprint string `json:"fingerprint,omitempty"`
	// Verified mirrors Forgejo: true once the owner proved possession of the
	// private key. Only verified keys mark signed commits as Verified. Unset
	// while unregistered, or when Forgejo (before 17) does not report it.
	// +optional
	Verified *bool `json:"verified,omitempty"`
	// VerificationURL is the settings page where the owner proves possession.
	VerificationURL string `json:"verificationURL,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="User",type=string,JSONPath=`.spec.user`
// +kubebuilder:printcolumn:name="Fingerprint",type=string,JSONPath=`.status.fingerprint`
// +kubebuilder:printcolumn:name="Verified",type=boolean,JSONPath=`.status.verified`
type ForgejoSSHKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SSHKeySpec   `json:"spec"`
	Status            SSHKeyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoSSHKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoSSHKey `json:"items"`
}

func init() { SchemeBuilder.Register(&ForgejoSSHKey{}, &ForgejoSSHKeyList{}) }
