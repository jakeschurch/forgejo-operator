package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type DeletionPolicy string

const (
	DeletionPolicyOrphan DeletionPolicy = "Orphan"
	DeletionPolicyDelete DeletionPolicy = "Delete"
)

type CommonSpec struct {
	// +kubebuilder:validation:MinLength=1
	ProviderRef string `json:"providerRef"`
	// providerNamespace is where the referenced ForgejoProvider (and its token
	// Secret) lives. Empty means this resource's own namespace (backward
	// compatible); set it to reference a provider shared from another namespace.
	// +optional
	ProviderNamespace string `json:"providerNamespace,omitempty"`
	// +kubebuilder:default=Orphan
	// +kubebuilder:validation:Enum=Orphan;Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`
	Prune          bool           `json:"prune,omitempty"`
}

type CommonStatus struct {
	RemoteID               string                        `json:"remoteID,omitempty"`
	ObservedGeneration     int64                         `json:"observedGeneration,omitempty"`
	GeneratedSecrets       []corev1.LocalObjectReference `json:"generatedSecrets,omitempty"`
	LastReconciliationTime *metav1.Time                  `json:"lastReconciliationTime,omitempty"`
	Conditions             []metav1.Condition            `json:"conditions,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.url == oldSelf.url",message="url is immutable"
type ForgejoProviderSpec struct {
	// +kubebuilder:validation:Pattern=`^https?://`
	URL string `json:"url"`
	// ExternalURL is the canonical user-facing URL for this installation.
	// API reconciliation still uses URL so in-cluster traffic stays private.
	// +kubebuilder:validation:Pattern=`^https?://`
	ExternalURL    string                   `json:"externalURL,omitempty"`
	TokenSecretRef corev1.SecretKeySelector `json:"tokenSecretRef"`
	RequestTimeout metav1.Duration          `json:"requestTimeout,omitempty"`
	// HumanAccessTokens lets ForgejoAccessTokens with accountType Human, in this
	// provider's namespace, mint tokens for the listed users. Unset refuses them.
	// +optional
	HumanAccessTokens *HumanAccessTokenPolicy `json:"humanAccessTokens,omitempty"`
}

// HumanAccessTokenPolicy is the provider-side half of human token minting.
// Forgejo only accepts password authentication on POST /users/{username}/tokens,
// and an admin API token (with or without Sudo) is rejected, so minting needs a
// site administrator's password. The operator only reads this credential. It
// never reads, sets, or resets the password of the human it mints for.
type HumanAccessTokenPolicy struct {
	// AllowedUsernames are the exact (case-sensitive) Forgejo usernames that may
	// receive tokens.
	// +kubebuilder:validation:MinItems=1
	AllowedUsernames []string `json:"allowedUsernames"`
	// AdminCredentialsSecretRef names a Secret in the provider's namespace with
	// "username" and "password" keys for a site administrator without WebAuthn or
	// TOTP enrolled, which Forgejo refuses or challenges on basic authentication.
	AdminCredentialsSecretRef corev1.LocalObjectReference `json:"adminCredentialsSecretRef"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ForgejoProvider struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              ForgejoProviderSpec `json:"spec"`
	Status            CommonStatus        `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoProviderList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoProvider `json:"items"`
}

// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.name == oldSelf.name",message="providerRef and name are immutable"
type OrganizationSpec struct {
	CommonSpec  `json:",inline"`
	Name        string `json:"name"`
	FullName    string `json:"fullName,omitempty"`
	Description string `json:"description,omitempty"`
	Visibility  string `json:"visibility,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ForgejoOrganization struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              OrganizationSpec `json:"spec"`
	Status            CommonStatus     `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoOrganizationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoOrganization `json:"items"`
}

// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.organization == oldSelf.organization && self.name == oldSelf.name",message="providerRef, organization, and name are immutable"
type TeamSpec struct {
	CommonSpec              `json:",inline"`
	Organization            string   `json:"organization"`
	Name                    string   `json:"name"`
	Description             string   `json:"description,omitempty"`
	Permission              string   `json:"permission,omitempty"`
	IncludesAllRepositories bool     `json:"includesAllRepositories,omitempty"`
	Units                   []string `json:"units,omitempty"`
	Repositories            []string `json:"repositories,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.organization == oldSelf.organization && self.username == oldSelf.username",message="providerRef, organization, and username are immutable"
type MembershipSpec struct {
	CommonSpec   `json:",inline"`
	Organization string   `json:"organization"`
	Username     string   `json:"username"`
	Teams        []string `json:"teams,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.username == oldSelf.username",message="providerRef and username are immutable"
type RobotAccountSpec struct {
	CommonSpec         `json:",inline"`
	Username           string `json:"username"`
	Email              string `json:"email,omitempty"`
	PasswordSecretName string `json:"passwordSecretName,omitempty"`
	RotationNonce      string `json:"rotationNonce,omitempty"`
}

// AccessTokenAccountType says which kind of account a ForgejoAccessToken mints for.
type AccessTokenAccountType string

const (
	AccessTokenAccountRobot AccessTokenAccountType = "Robot"
	AccessTokenAccountHuman AccessTokenAccountType = "Human"
)

// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.username == oldSelf.username && self.name == oldSelf.name",message="providerRef, username, and name are immutable"
// +kubebuilder:validation:XValidation:rule="(has(self.accountType) ? self.accountType : 'Robot') == (has(oldSelf.accountType) ? oldSelf.accountType : 'Robot')",message="accountType is immutable"
type AccessTokenSpec struct {
	CommonSpec `json:",inline"`
	// AccountType Robot mints with the password of a ForgejoRobotAccount in this
	// namespace. Human is an explicit opt-in to mint for an existing person, and
	// also requires the username in the provider's humanAccessTokens allowlist.
	// +kubebuilder:default=Robot
	// +kubebuilder:validation:Enum=Robot;Human
	AccountType   AccessTokenAccountType `json:"accountType,omitempty"`
	Username      string                 `json:"username"`
	Name          string                 `json:"name"`
	Scopes        []string               `json:"scopes,omitempty"`
	SecretName    string                 `json:"secretName,omitempty"`
	RotationNonce string                 `json:"rotationNonce,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.owner == oldSelf.owner && self.name == oldSelf.name",message="providerRef, owner, and name are immutable"
type RepositorySpec struct {
	CommonSpec    `json:",inline"`
	Owner         string            `json:"owner"`
	Name          string            `json:"name"`
	Description   string            `json:"description,omitempty"`
	Visibility    string            `json:"visibility,omitempty"`
	DefaultBranch string            `json:"defaultBranch,omitempty"`
	Topics        []string          `json:"topics,omitempty"`
	Features      map[string]bool   `json:"features,omitempty"`
	Import        *RepositoryImport `json:"import,omitempty"`
	// AllowManualMerge permits recording a merge already performed through Git.
	// Omission leaves the remote setting unchanged; false explicitly disables it.
	AllowManualMerge *bool `json:"allowManualMerge,omitempty"`
	// AutodetectManualMerge lets Forgejo mark PRs merged after a Git push.
	// Omission leaves the remote setting unchanged; false explicitly disables it.
	AutodetectManualMerge *bool `json:"autodetectManualMerge,omitempty"`
}
type RepositoryImport struct {
	CloneURL             string                    `json:"cloneURL"`
	CredentialsSecretRef *corev1.SecretKeySelector `json:"credentialsSecretRef,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.owner == oldSelf.owner && self.repository == oldSelf.repository && self.username == oldSelf.username",message="remote identity fields are immutable"
type CollaboratorSpec struct {
	CommonSpec `json:",inline"`
	Owner      string `json:"owner"`
	Repository string `json:"repository"`
	Username   string `json:"username"`
	Permission string `json:"permission"`
}

// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.owner == oldSelf.owner && self.repository == oldSelf.repository && self.title == oldSelf.title",message="remote identity fields are immutable"
type DeployKeySpec struct {
	CommonSpec         `json:",inline"`
	Owner              string                   `json:"owner"`
	Repository         string                   `json:"repository"`
	Title              string                   `json:"title"`
	PublicKeySecretRef corev1.SecretKeySelector `json:"publicKeySecretRef"`
	ReadOnly           bool                     `json:"readOnly,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.owner == oldSelf.owner && self.repository == oldSelf.repository && self.url == oldSelf.url",message="remote identity fields are immutable"
type WebhookSpec struct {
	CommonSpec          `json:",inline"`
	Owner               string                    `json:"owner"`
	Repository          string                    `json:"repository,omitempty"`
	URL                 string                    `json:"url"`
	Events              []string                  `json:"events,omitempty"`
	Active              *bool                     `json:"active,omitempty"`
	SecretRef           *corev1.SecretKeySelector `json:"secretRef,omitempty"`
	GeneratedSecretName string                    `json:"generatedSecretName,omitempty"`
	RotationNonce       string                    `json:"rotationNonce,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.owner == oldSelf.owner && self.repository == oldSelf.repository && self.destinationURL == oldSelf.destinationURL",message="remote identity fields are immutable"
type PushMirrorSpec struct {
	CommonSpec           `json:",inline"`
	Owner                string                   `json:"owner"`
	Repository           string                   `json:"repository"`
	DestinationURL       string                   `json:"destinationURL"`
	Interval             string                   `json:"interval,omitempty"`
	SyncOnCommit         bool                     `json:"syncOnCommit,omitempty"`
	CredentialsSecretRef corev1.SecretKeySelector `json:"credentialsSecretRef"`
	// RemoteUsername is the basic-auth username Forgejo stores alongside the
	// credential. Leaving it empty makes Forgejo store the remote as
	// "https://:TOKEN@host/...", and GitHub rejects empty-username basic auth:
	// it falls back to anonymous, and a private repository then answers
	// "Repository not found", which git surfaces as "Authentication failed".
	// For a GitHub personal access token set this to the token itself, or to
	// any non-empty placeholder such as "x-access-token".
	//
	// DANGER: a Forgejo push mirror is `git push --mirror`. It makes the
	// destination IDENTICAL to the source, DELETING every ref the source
	// lacks. On 2026-09-22 this exact fix was applied by hand to jake/homelab
	// and the first sync DELETED 162 refs from github.com/jakeschurch/homelab
	// (82 branches + 80 tags); they had to be restored from a local clone.
	// Setting this field on a mirror that has never authenticated successfully
	// is what ARMS that first destructive sync. Reconcile the source's refs
	// with the destination's BEFORE this value reaches a live mirror.
	//
	// Changing this value, like changing the referenced credential, rotates
	// the mirror (delete and recreate) only once the operator has proved that
	// the destination holds no ref whose name or object is missing from the
	// source and that the mirror's last sync succeeded; otherwise the mirror is
	// left untouched and the resource reports Degraded. See reconcile().
	// +optional
	RemoteUsername string `json:"remoteUsername,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.owner == oldSelf.owner && self.repository == oldSelf.repository && self.branch == oldSelf.branch",message="remote identity fields are immutable"
type BranchProtectionSpec struct {
	CommonSpec             `json:",inline"`
	Owner                  string   `json:"owner"`
	Repository             string   `json:"repository"`
	Branch                 string   `json:"branch"`
	RequiredApprovals      int      `json:"requiredApprovals,omitempty"`
	RequiredStatusContexts []string `json:"requiredStatusContexts,omitempty"`
	EnablePush             bool     `json:"enablePush,omitempty"`
	EnableMerge            bool     `json:"enableMerge,omitempty"`
	// PushAllowlistUsers, with enablePush, limits direct pushes to these users;
	// everyone else lands through a pull request. Empty leaves push open to all
	// writers.
	PushAllowlistUsers []string `json:"pushAllowlistUsers,omitempty"`
	// PushAllowlistDeployKeys, with an allowlist, also lets the repository's
	// write deploy keys push. Forgejo has no per-key list: it is all or none.
	PushAllowlistDeployKeys bool `json:"pushAllowlistDeployKeys,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.owner == oldSelf.owner && self.repository == oldSelf.repository && self.pattern == oldSelf.pattern",message="remote identity fields are immutable"
type TagProtectionSpec struct {
	CommonSpec     `json:",inline"`
	Owner          string   `json:"owner"`
	Repository     string   `json:"repository"`
	Pattern        string   `json:"pattern"`
	WhitelistUsers []string `json:"whitelistUsers,omitempty"`
	WhitelistTeams []string `json:"whitelistTeams,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="self.providerRef == oldSelf.providerRef && self.owner == oldSelf.owner && self.repository == oldSelf.repository && self.name == oldSelf.name",message="remote identity fields are immutable"
type LabelSpec struct {
	CommonSpec  `json:",inline"`
	Owner       string `json:"owner"`
	Repository  string `json:"repository,omitempty"`
	Name        string `json:"name"`
	Color       string `json:"color"`
	Description string `json:"description,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ForgejoTeam struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TeamSpec     `json:"spec"`
	Status            CommonStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoTeamList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoTeam `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ForgejoMembership struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              MembershipSpec `json:"spec"`
	Status            CommonStatus   `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoMembershipList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoMembership `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ForgejoRobotAccount struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              RobotAccountSpec `json:"spec"`
	Status            CommonStatus     `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoRobotAccountList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoRobotAccount `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ForgejoAccessToken struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AccessTokenSpec `json:"spec"`
	Status            CommonStatus    `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoAccessTokenList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoAccessToken `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ForgejoRepository struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              RepositorySpec `json:"spec"`
	Status            CommonStatus   `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoRepositoryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoRepository `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ForgejoCollaborator struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              CollaboratorSpec `json:"spec"`
	Status            CommonStatus     `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoCollaboratorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoCollaborator `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ForgejoDeployKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              DeployKeySpec `json:"spec"`
	Status            CommonStatus  `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoDeployKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoDeployKey `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ForgejoWebhook struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              WebhookSpec  `json:"spec"`
	Status            CommonStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoWebhookList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoWebhook `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ForgejoPushMirror struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              PushMirrorSpec   `json:"spec"`
	Status            PushMirrorStatus `json:"status,omitempty"`
}

// PushMirrorStatus is CommonStatus plus the fingerprint of the credential the
// live Forgejo mirror was last created or observed with.
type PushMirrorStatus struct {
	CommonStatus `json:",inline"`
	// CredentialHash is the hex SHA-256 of remoteUsername + NUL + credential
	// that the live mirror holds. Forgejo never returns a mirror's stored
	// credential, so this is how a rotation of the referenced Secret is
	// detected. It never contains the credential itself.
	// +optional
	CredentialHash string `json:"credentialHash,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoPushMirrorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoPushMirror `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ForgejoBranchProtection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              BranchProtectionSpec `json:"spec"`
	Status            CommonStatus         `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoBranchProtectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoBranchProtection `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ForgejoTagProtection struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TagProtectionSpec `json:"spec"`
	Status            CommonStatus      `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoTagProtectionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoTagProtection `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type ForgejoLabel struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              LabelSpec    `json:"spec"`
	Status            CommonStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
type ForgejoLabelList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ForgejoLabel `json:"items"`
}

func init() {
	SchemeBuilder.Register(
		&ForgejoGPGKey{}, &ForgejoGPGKeyList{},
		&ForgejoProvider{}, &ForgejoProviderList{}, &ForgejoOrganization{}, &ForgejoOrganizationList{},
		&ForgejoTeam{}, &ForgejoTeamList{}, &ForgejoMembership{}, &ForgejoMembershipList{},
		&ForgejoRobotAccount{}, &ForgejoRobotAccountList{}, &ForgejoAccessToken{}, &ForgejoAccessTokenList{},
		&ForgejoRepository{}, &ForgejoRepositoryList{}, &ForgejoCollaborator{}, &ForgejoCollaboratorList{},
		&ForgejoDeployKey{}, &ForgejoDeployKeyList{}, &ForgejoWebhook{}, &ForgejoWebhookList{},
		&ForgejoPushMirror{}, &ForgejoPushMirrorList{}, &ForgejoBranchProtection{}, &ForgejoBranchProtectionList{},
		&ForgejoTagProtection{}, &ForgejoTagProtectionList{}, &ForgejoLabel{}, &ForgejoLabelList{},
	)
}
