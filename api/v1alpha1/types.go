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

type ForgejoProviderSpec struct {
	// +kubebuilder:validation:Pattern=`^https?://`
	URL            string                   `json:"url"`
	TokenSecretRef corev1.SecretKeySelector `json:"tokenSecretRef"`
	RequestTimeout metav1.Duration          `json:"requestTimeout,omitempty"`
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
type MembershipSpec struct {
	CommonSpec   `json:",inline"`
	Organization string   `json:"organization"`
	Username     string   `json:"username"`
	Teams        []string `json:"teams,omitempty"`
}
type RobotAccountSpec struct {
	CommonSpec         `json:",inline"`
	Username           string `json:"username"`
	Email              string `json:"email,omitempty"`
	PasswordSecretName string `json:"passwordSecretName,omitempty"`
	RotationNonce      string `json:"rotationNonce,omitempty"`
}
type AccessTokenSpec struct {
	CommonSpec    `json:",inline"`
	Username      string   `json:"username"`
	Name          string   `json:"name"`
	Scopes        []string `json:"scopes,omitempty"`
	SecretName    string   `json:"secretName,omitempty"`
	RotationNonce string   `json:"rotationNonce,omitempty"`
}
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
}
type RepositoryImport struct {
	CloneURL             string                    `json:"cloneURL"`
	CredentialsSecretRef *corev1.SecretKeySelector `json:"credentialsSecretRef,omitempty"`
}
type CollaboratorSpec struct {
	CommonSpec `json:",inline"`
	Owner      string `json:"owner"`
	Repository string `json:"repository"`
	Username   string `json:"username"`
	Permission string `json:"permission"`
}
type DeployKeySpec struct {
	CommonSpec         `json:",inline"`
	Owner              string                   `json:"owner"`
	Repository         string                   `json:"repository"`
	Title              string                   `json:"title"`
	PublicKeySecretRef corev1.SecretKeySelector `json:"publicKeySecretRef"`
	ReadOnly           bool                     `json:"readOnly,omitempty"`
}
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
type PushMirrorSpec struct {
	CommonSpec           `json:",inline"`
	Owner                string                   `json:"owner"`
	Repository           string                   `json:"repository"`
	DestinationURL       string                   `json:"destinationURL"`
	Interval             string                   `json:"interval,omitempty"`
	SyncOnCommit         bool                     `json:"syncOnCommit,omitempty"`
	CredentialsSecretRef corev1.SecretKeySelector `json:"credentialsSecretRef"`
}
type BranchProtectionSpec struct {
	CommonSpec             `json:",inline"`
	Owner                  string   `json:"owner"`
	Repository             string   `json:"repository"`
	Branch                 string   `json:"branch"`
	RequiredApprovals      int      `json:"requiredApprovals,omitempty"`
	RequiredStatusContexts []string `json:"requiredStatusContexts,omitempty"`
	EnablePush             bool     `json:"enablePush,omitempty"`
	EnableMerge            bool     `json:"enableMerge,omitempty"`
}
type TagProtectionSpec struct {
	CommonSpec     `json:",inline"`
	Owner          string   `json:"owner"`
	Repository     string   `json:"repository"`
	Pattern        string   `json:"pattern"`
	WhitelistUsers []string `json:"whitelistUsers,omitempty"`
	WhitelistTeams []string `json:"whitelistTeams,omitempty"`
}
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
	Spec              PushMirrorSpec `json:"spec"`
	Status            CommonStatus   `json:"status,omitempty"`
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
		&ForgejoProvider{}, &ForgejoProviderList{}, &ForgejoOrganization{}, &ForgejoOrganizationList{},
		&ForgejoTeam{}, &ForgejoTeamList{}, &ForgejoMembership{}, &ForgejoMembershipList{},
		&ForgejoRobotAccount{}, &ForgejoRobotAccountList{}, &ForgejoAccessToken{}, &ForgejoAccessTokenList{},
		&ForgejoRepository{}, &ForgejoRepositoryList{}, &ForgejoCollaborator{}, &ForgejoCollaboratorList{},
		&ForgejoDeployKey{}, &ForgejoDeployKeyList{}, &ForgejoWebhook{}, &ForgejoWebhookList{},
		&ForgejoPushMirror{}, &ForgejoPushMirrorList{}, &ForgejoBranchProtection{}, &ForgejoBranchProtectionList{},
		&ForgejoTagProtection{}, &ForgejoTagProtectionList{}, &ForgejoLabel{}, &ForgejoLabelList{},
	)
}
