package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// GPGKeySpec describes an operator-owned signing key. Remote identity and Secret
// coordinates are immutable: changing them would strand credentials.
// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.user == oldSelf.user && self.identity == oldSelf.identity && self.secretRef == oldSelf.secretRef",message="provider, user, identity and secretRef are immutable"
// +kubebuilder:validation:XValidation:rule="has(self.providerNamespace) == has(oldSelf.providerNamespace) && (!has(self.providerNamespace) || self.providerNamespace == oldSelf.providerNamespace)",message="providerNamespace is immutable"
// +kubebuilder:validation:XValidation:rule="(has(self.algorithm) ? self.algorithm : 'ed25519') == (has(oldSelf.algorithm) ? oldSelf.algorithm : 'ed25519')",message="algorithm is immutable"
type GPGKeySpec struct {
	// +kubebuilder:validation:MinLength=1
	ProviderRef string `json:"providerRef"`
	// +optional
	ProviderNamespace string `json:"providerNamespace,omitempty"`
	// +kubebuilder:validation:MinLength=1
	User     string      `json:"user"`
	Identity GPGIdentity `json:"identity"`
	// ed25519 generates a v4 EdDSA signing key and a Curve25519 encryption subkey.
	// +kubebuilder:default=ed25519
	// +kubebuilder:validation:Enum=ed25519;rsa4096
	Algorithm string       `json:"algorithm,omitempty"`
	SecretRef GPGSecretRef `json:"secretRef"`
	// Orphan retains remote public keys on deletion, preserving historical verification.
	// +kubebuilder:default=Orphan
	// +kubebuilder:validation:Enum=Orphan;Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
	// +optional
	Rotation *GPGKeyRotation `json:"rotation,omitempty"`
}

type GPGIdentity struct {
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:Pattern=`^[^()<>]+$`
	Name string `json:"name"`
	// Email must be an activated email address on the target Forgejo account.
	// +kubebuilder:validation:MinLength=3
	Email string `json:"email"`
}

type GPGSecretRef struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Keys defaults to privateKey, publicKey, keyID and fingerprint.
	// +optional
	Keys *GPGSecretKeys `json:"keys,omitempty"`
}

type GPGSecretKeys struct {
	PrivateKey  string `json:"privateKey,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	KeyID       string `json:"keyID,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type GPGKeyRotation struct {
	// After is the age at which a new key is generated. Unset disables rotation.
	// +optional
	After *metav1.Duration `json:"after,omitempty"`
	// GracePeriod retains the previous public key for verification. Default 24h.
	// Rotation waits for retirement before generating another key.
	// +optional
	GracePeriod *metav1.Duration `json:"gracePeriod,omitempty"`
}

type GPGKeyStatus struct {
	CommonStatus `json:",inline"`
	KeyID        string `json:"keyID,omitempty"`
	Fingerprint  string `json:"fingerprint,omitempty"`
	// ManagedKeyIDs mirrors protected ForgejoGPGKeyState for humans.
	// Status is never trusted for registration, rotation, retirement or deletion.
	ManagedKeyIDs []string `json:"managedKeyIDs,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ForgejoGPGKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              GPGKeySpec   `json:"spec"`
	Status            GPGKeyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoGPGKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoGPGKey `json:"items"`
}
