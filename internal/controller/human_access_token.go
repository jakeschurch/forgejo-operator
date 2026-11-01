package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	"github.com/jakeschurch/forgejo-operator/internal/credentials"
	forgeapi "github.com/jakeschurch/forgejo-operator/internal/forgejo"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// humanTokenPolicy returns the humanAccessTokens policy of the object's provider.
// The provider is looked up in the object's own namespace, matching the client
// Reconcile built, so the policy and the API endpoint are always the same provider.
func (r *managedReconciler) humanTokenPolicy(ctx context.Context, v *forgev1.ForgejoAccessToken) (*forgev1.HumanAccessTokenPolicy, error) {
	if v.Spec.ProviderNamespace != "" && v.Spec.ProviderNamespace != v.Namespace {
		return nil, errors.New("human access tokens must be in the same namespace as their provider")
	}
	var provider forgev1.ForgejoProvider
	if err := r.Get(ctx, types.NamespacedName{Namespace: v.Namespace, Name: v.Spec.ProviderRef}, &provider); err != nil {
		return nil, fmt.Errorf("get provider: %w", err)
	}
	if provider.Spec.HumanAccessTokens == nil {
		return nil, errors.New("provider does not enable humanAccessTokens")
	}
	return provider.Spec.HumanAccessTokens, nil
}

// authorizeHumanToken makes every check that needs no credential and no request
// to Forgejo, so a refused CR never touches the administrator password.
func (r *managedReconciler) authorizeHumanToken(ctx context.Context, v *forgev1.ForgejoAccessToken) (*forgev1.HumanAccessTokenPolicy, error) {
	policy, err := r.humanTokenPolicy(ctx, v)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(policy.AllowedUsernames, v.Spec.Username) {
		return nil, errors.New("access token username is not in the provider's humanAccessTokens.allowedUsernames")
	}
	var robots forgev1.ForgejoRobotAccountList
	if err := r.List(ctx, &robots, client.InNamespace(v.Namespace)); err != nil {
		return nil, fmt.Errorf("list robot accounts: %w", err)
	}
	for i := range robots.Items {
		if robots.Items[i].Spec.ProviderRef == v.Spec.ProviderRef && robots.Items[i].Spec.Username == v.Spec.Username {
			return nil, errors.New("access token username is a managed robot account; use accountType Robot")
		}
	}
	if len(v.Spec.Scopes) == 0 {
		return nil, errors.New("human access tokens require at least one scope")
	}
	return policy, nil
}

func (r *managedReconciler) adminCredentials(ctx context.Context, namespace string, policy *forgev1.HumanAccessTokenPolicy) (string, string, error) {
	read := func(key string) (string, error) {
		return r.secretValue(ctx, namespace, corev1.SecretKeySelector{LocalObjectReference: policy.AdminCredentialsSecretRef, Key: key}, key)
	}
	username, err := read("username")
	if err != nil {
		return "", "", fmt.Errorf("read administrator credential: %w", err)
	}
	password, err := read("password")
	if err != nil {
		return "", "", fmt.Errorf("read administrator credential: %w", err)
	}
	return username, password, nil
}

// recordedTokenID returns the token id this CR minted, if it recorded one. A
// remote ID in any other form did not come from a mint and addresses no token.
func recordedTokenID(remoteID string) (string, bool) {
	id, err := strconv.ParseInt(remoteID, 10, 64)
	if err != nil || id <= 0 {
		return "", false
	}
	return strconv.FormatInt(id, 10), true
}

func revokeAccessToken(ctx context.Context, api *forgeapi.Client, v *forgev1.ForgejoAccessToken, authUser, authPassword, id string) error {
	path := "users/" + esc(v.Spec.Username) + "/tokens/" + id
	err := api.DoBasic(ctx, http.MethodDelete, path, authUser, authPassword, nil, nil)
	if isNotFound(err) {
		return nil
	}
	return err
}

func (r *managedReconciler) reconcileHumanAccessToken(ctx context.Context, api *forgeapi.Client, v *forgev1.ForgejoAccessToken) (string, error) {
	policy, err := r.authorizeHumanToken(ctx, v)
	if err != nil {
		return "", err
	}
	name := v.Spec.SecretName
	if name == "" {
		name = v.Name + "-token"
	}
	var existing corev1.Secret
	err = r.Get(ctx, types.NamespacedName{Namespace: v.Namespace, Name: name}, &existing)
	if err != nil && !apierrors.IsNotFound(err) {
		return "", err
	}
	exists := err == nil
	rotating := false
	if exists {
		nonce, managed := existing.Annotations[credentials.RotationNonceAnnotation]
		if !managed {
			// Without this, secretName could overwrite an unrelated Secret.
			return "", errors.New("access token secretName refers to a Secret this operator did not create")
		}
		rotating = nonce != v.Spec.RotationNonce
		if !rotating && len(existing.Data["token"]) > 0 {
			if id, ok := recordedTokenID(v.Status.RemoteID); ok {
				return id, nil
			}
			return v.Spec.Username + "/" + v.Spec.Name, nil
		}
	}
	adminUser, adminPassword, err := r.adminCredentials(ctx, v.Namespace, policy)
	if err != nil {
		return "", err
	}
	if id, ok := recordedTokenID(v.Status.RemoteID); ok && rotating {
		if err := revokeAccessToken(ctx, api, v, adminUser, adminPassword, id); err != nil {
			return "", fmt.Errorf("revoke rotated token: %w", err)
		}
	}
	var created struct {
		ID   int64  `json:"id"`
		SHA1 string `json:"sha1"`
	}
	path := "users/" + esc(v.Spec.Username) + "/tokens"
	if err := api.DoBasic(ctx, http.MethodPost, path, adminUser, adminPassword, map[string]any{"name": v.Spec.Name, "scopes": v.Spec.Scopes}, &created); err != nil {
		var apiErr *forgeapi.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest {
			return "", fmt.Errorf("token name already used on this account, or invalid scopes; the operator only revokes tokens it recorded, so remove a conflicting token in Forgejo: %w", err)
		}
		return "", err
	}
	if created.SHA1 == "" {
		return "", errors.New("token response had no value")
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: v.Namespace, Annotations: map[string]string{credentials.RotationNonceAnnotation: v.Spec.RotationNonce}}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"token": []byte(created.SHA1)}}
	if exists {
		secret.ResourceVersion = existing.ResourceVersion
		err = r.Update(ctx, secret)
	} else {
		err = r.Create(ctx, secret)
	}
	id := strconv.FormatInt(created.ID, 10)
	if err != nil {
		// The value is unrecoverable, so an unstored token is an unusable live
		// credential on a person's account that also blocks its own name.
		if revokeErr := revokeAccessToken(ctx, api, v, adminUser, adminPassword, id); revokeErr != nil {
			return "", fmt.Errorf("store token: %w; revoke unstored token %s: %w", err, id, revokeErr)
		}
		return "", fmt.Errorf("store token: %w", err)
	}
	return id, nil
}

// deleteHumanAccessToken skips the allowlist on purpose: revoking only reduces
// access, and a recorded id exists only for a CR that passed it when minted.
func (r *managedReconciler) deleteHumanAccessToken(ctx context.Context, api *forgeapi.Client, v *forgev1.ForgejoAccessToken, remoteID string) error {
	id, ok := recordedTokenID(remoteID)
	if !ok {
		return nil
	}
	policy, err := r.humanTokenPolicy(ctx, v)
	if err != nil {
		return err
	}
	adminUser, adminPassword, err := r.adminCredentials(ctx, v.Namespace, policy)
	if err != nil {
		return err
	}
	return revokeAccessToken(ctx, api, v, adminUser, adminPassword, id)
}
