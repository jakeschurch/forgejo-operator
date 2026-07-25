package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	forgeapi "github.com/jakeschurch/forgejo-operator/internal/forgejo"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const finalizer = "forgejo.jakeschurch.com/remote-delete"

type Reconciler struct{ client.Client }

func (r *Reconciler) ensureUniqueOwner(ctx context.Context, object client.Object) error {
	list := listFor(object)
	if list == nil {
		return nil
	}
	if err := r.List(ctx, list, client.InNamespace(object.GetNamespace())); err != nil {
		return fmt.Errorf("list duplicate owners: %w", err)
	}
	items, err := apimeta.ExtractList(list)
	if err != nil {
		return fmt.Errorf("inspect duplicate owners: %w", err)
	}
	key := naturalKey(object)
	for _, item := range items {
		other, ok := item.(client.Object)
		if ok && other.GetName() != object.GetName() && naturalKey(other) == key {
			return fmt.Errorf("remote natural key %q is already claimed by %s", key, other.GetName())
		}
	}
	return nil
}

func listFor(object client.Object) client.ObjectList {
	switch object.(type) {
	case *forgev1.ForgejoOrganization:
		return &forgev1.ForgejoOrganizationList{}
	case *forgev1.ForgejoRepository:
		return &forgev1.ForgejoRepositoryList{}
	case *forgev1.ForgejoTeam:
		return &forgev1.ForgejoTeamList{}
	case *forgev1.ForgejoMembership:
		return &forgev1.ForgejoMembershipList{}
	case *forgev1.ForgejoRobotAccount:
		return &forgev1.ForgejoRobotAccountList{}
	case *forgev1.ForgejoAccessToken:
		return &forgev1.ForgejoAccessTokenList{}
	case *forgev1.ForgejoCollaborator:
		return &forgev1.ForgejoCollaboratorList{}
	case *forgev1.ForgejoDeployKey:
		return &forgev1.ForgejoDeployKeyList{}
	case *forgev1.ForgejoWebhook:
		return &forgev1.ForgejoWebhookList{}
	case *forgev1.ForgejoPushMirror:
		return &forgev1.ForgejoPushMirrorList{}
	case *forgev1.ForgejoBranchProtection:
		return &forgev1.ForgejoBranchProtectionList{}
	case *forgev1.ForgejoTagProtection:
		return &forgev1.ForgejoTagProtectionList{}
	case *forgev1.ForgejoLabel:
		return &forgev1.ForgejoLabelList{}
	default:
		return nil
	}
}

func naturalKey(object client.Object) string {
	switch v := object.(type) {
	case *forgev1.ForgejoOrganization:
		return v.Spec.ProviderRef + "/" + v.Spec.Name
	case *forgev1.ForgejoRepository:
		return v.Spec.ProviderRef + "/" + v.Spec.Owner + "/" + v.Spec.Name
	case *forgev1.ForgejoTeam:
		return v.Spec.ProviderRef + "/" + v.Spec.Organization + "/" + v.Spec.Name
	case *forgev1.ForgejoMembership:
		return v.Spec.ProviderRef + "/" + v.Spec.Organization + "/" + v.Spec.Username
	case *forgev1.ForgejoRobotAccount:
		return v.Spec.ProviderRef + "/" + v.Spec.Username
	case *forgev1.ForgejoAccessToken:
		return v.Spec.ProviderRef + "/" + v.Spec.Username + "/" + v.Spec.Name
	case *forgev1.ForgejoCollaborator:
		return v.Spec.ProviderRef + "/" + v.Spec.Owner + "/" + v.Spec.Repository + "/" + v.Spec.Username
	case *forgev1.ForgejoDeployKey:
		return v.Spec.ProviderRef + "/" + v.Spec.Owner + "/" + v.Spec.Repository + "/" + v.Spec.Title
	case *forgev1.ForgejoWebhook:
		return v.Spec.ProviderRef + "/" + v.Spec.Owner + "/" + v.Spec.Repository + "/" + v.Spec.URL
	case *forgev1.ForgejoPushMirror:
		return v.Spec.ProviderRef + "/" + v.Spec.Owner + "/" + v.Spec.Repository + "/" + v.Spec.DestinationURL
	case *forgev1.ForgejoBranchProtection:
		return v.Spec.ProviderRef + "/" + v.Spec.Owner + "/" + v.Spec.Repository + "/" + v.Spec.Branch
	case *forgev1.ForgejoTagProtection:
		return v.Spec.ProviderRef + "/" + v.Spec.Owner + "/" + v.Spec.Repository + "/" + v.Spec.Pattern
	case *forgev1.ForgejoLabel:
		return v.Spec.ProviderRef + "/" + v.Spec.Owner + "/" + v.Spec.Repository + "/" + v.Spec.Name
	default:
		return ""
	}
}

func (r *Reconciler) readSecret(ctx context.Context, namespace string, ref corev1.SecretKeySelector, defaultKey string) (string, error) {
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, &secret); err != nil {
		return "", fmt.Errorf("get referenced Secret: %w", err)
	}
	key := ref.Key
	if key == "" {
		key = defaultKey
	}
	if len(secret.Data[key]) == 0 {
		return "", fmt.Errorf("referenced Secret key %q is empty", key)
	}
	return string(secret.Data[key]), nil
}

func ManagedSetups(base Reconciler) []func(ctrl.Manager) error {
	objects := []func() client.Object{
		func() client.Object { return &forgev1.ForgejoTeam{} },
		func() client.Object { return &forgev1.ForgejoMembership{} },
		func() client.Object { return &forgev1.ForgejoRobotAccount{} },
		func() client.Object { return &forgev1.ForgejoAccessToken{} },
		func() client.Object { return &forgev1.ForgejoCollaborator{} },
		func() client.Object { return &forgev1.ForgejoDeployKey{} },
		func() client.Object { return &forgev1.ForgejoWebhook{} },
		func() client.Object { return &forgev1.ForgejoPushMirror{} },
		func() client.Object { return &forgev1.ForgejoBranchProtection{} },
		func() client.Object { return &forgev1.ForgejoTagProtection{} },
		func() client.Object { return &forgev1.ForgejoLabel{} },
	}
	out := make([]func(ctrl.Manager) error, 0, len(objects))
	for _, factory := range objects {
		reconciler := &managedReconciler{Reconciler: base, newObject: factory}
		out = append(out, reconciler.SetupWithManager)
	}
	return out
}

func (r *Reconciler) providerClient(ctx context.Context, namespace, name string) (*forgeapi.Client, error) {
	var provider forgev1.ForgejoProvider
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &provider); err != nil {
		return nil, fmt.Errorf("get provider: %w", err)
	}
	var secret corev1.Secret
	ref := provider.Spec.TokenSecretRef
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, &secret); err != nil {
		return nil, fmt.Errorf("get provider credential: %w", err)
	}
	key := ref.Key
	if key == "" {
		key = "token"
	}
	token := secret.Data[key]
	if len(token) == 0 {
		return nil, errors.New("provider credential key is empty")
	}
	timeout := provider.Spec.RequestTimeout.Duration
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return forgeapi.New(provider.Spec.URL, string(token), forgeapi.WithHTTPClient(&http.Client{Timeout: timeout}))
}

type ProviderReconciler struct{ Reconciler }

func (r *ProviderReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var object forgev1.ForgejoProvider
	if err := r.Get(ctx, req.NamespacedName, &object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	api, err := r.providerClient(ctx, object.Namespace, object.Name)
	if err == nil {
		err = api.Do(ctx, http.MethodGet, "version", nil, nil)
	}
	setStatus(&object.Status, object.Generation, err)
	if updateErr := r.Status().Update(ctx, &object); updateErr != nil {
		return ctrl.Result{}, updateErr
	}
	if err != nil {
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	return ctrl.Result{RequeueAfter: 10 * time.Minute}, nil
}
func (r *ProviderReconciler) SetupWithManager(m ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(m).For(&forgev1.ForgejoProvider{}).Complete(r)
}

type OrganizationReconciler struct{ Reconciler }

func (r *OrganizationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var object forgev1.ForgejoOrganization
	if err := r.Get(ctx, req.NamespacedName, &object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	api, err := r.providerClient(ctx, object.Namespace, object.Spec.ProviderRef)
	if err == nil {
		err = r.ensureUniqueOwner(ctx, &object)
	}
	if err == nil && !object.DeletionTimestamp.IsZero() {
		if contains(object.Finalizers, finalizer) {
			if object.Spec.DeletionPolicy == forgev1.DeletionPolicyDelete {
				err = api.Do(ctx, http.MethodDelete, "orgs/"+esc(object.Spec.Name), nil, nil)
				if isNotFound(err) {
					err = nil
				}
			}
			if err == nil {
				object.Finalizers = remove(object.Finalizers, finalizer)
				return ctrl.Result{}, r.Update(ctx, &object)
			}
		}
		return ctrl.Result{}, nil
	}
	if err == nil && object.Spec.DeletionPolicy == forgev1.DeletionPolicyDelete && !contains(object.Finalizers, finalizer) {
		object.Finalizers = append(object.Finalizers, finalizer)
		if err := r.Update(ctx, &object); err != nil {
			return ctrl.Result{}, err
		}
	}
	if err == nil {
		var remote struct {
			ID int64 `json:"id"`
		}
		err = api.Do(ctx, http.MethodGet, "orgs/"+object.Spec.Name, nil, &remote)
		var apiErr *forgeapi.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			err = api.Do(ctx, http.MethodPost, "orgs", map[string]any{"username": object.Spec.Name, "full_name": object.Spec.FullName, "description": object.Spec.Description, "visibility": object.Spec.Visibility}, &remote)
		} else if err == nil {
			err = api.Do(ctx, http.MethodPatch, "orgs/"+object.Spec.Name, map[string]any{"full_name": object.Spec.FullName, "description": object.Spec.Description, "visibility": object.Spec.Visibility}, nil)
		}
		if err == nil {
			object.Status.RemoteID = fmt.Sprint(remote.ID)
		}
	}
	setStatus(&object.Status, object.Generation, err)
	if updateErr := r.Status().Update(ctx, &object); updateErr != nil {
		return ctrl.Result{}, updateErr
	}
	if err != nil {
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	return ctrl.Result{RequeueAfter: 10 * time.Minute}, nil
}
func (r *OrganizationReconciler) SetupWithManager(m ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(m).For(&forgev1.ForgejoOrganization{}).Complete(r)
}

type RepositoryReconciler struct{ Reconciler }

func (r *RepositoryReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var object forgev1.ForgejoRepository
	if err := r.Get(ctx, req.NamespacedName, &object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	api, err := r.providerClient(ctx, object.Namespace, object.Spec.ProviderRef)
	if err == nil {
		err = r.ensureUniqueOwner(ctx, &object)
	}
	if err == nil && !object.DeletionTimestamp.IsZero() {
		if contains(object.Finalizers, finalizer) {
			if object.Spec.DeletionPolicy == forgev1.DeletionPolicyDelete {
				err = api.Do(ctx, http.MethodDelete, repoPath(object.Spec.Owner, object.Spec.Name), nil, nil)
				if isNotFound(err) {
					err = nil
				}
			}
			if err == nil {
				object.Finalizers = remove(object.Finalizers, finalizer)
				return ctrl.Result{}, r.Update(ctx, &object)
			}
		}
		return ctrl.Result{}, nil
	}
	if err == nil && object.Spec.DeletionPolicy == forgev1.DeletionPolicyDelete && !contains(object.Finalizers, finalizer) {
		object.Finalizers = append(object.Finalizers, finalizer)
		if err := r.Update(ctx, &object); err != nil {
			return ctrl.Result{}, err
		}
	}
	if err == nil {
		path := "repos/" + object.Spec.Owner + "/" + object.Spec.Name
		var remote struct {
			ID int64 `json:"id"`
		}
		err = api.Do(ctx, http.MethodGet, path, nil, &remote)
		var apiErr *forgeapi.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			if object.Spec.Import != nil {
				payload := map[string]any{"clone_addr": object.Spec.Import.CloneURL, "repo_owner": object.Spec.Owner, "repo_name": object.Spec.Name, "description": object.Spec.Description}
				if object.Spec.Import.CredentialsSecretRef != nil {
					credential, secretErr := r.readSecret(ctx, object.Namespace, *object.Spec.Import.CredentialsSecretRef, "token")
					if secretErr != nil {
						err = secretErr
					} else {
						payload["auth_token"] = credential
					}
				}
				if err == nil {
					err = api.Do(ctx, http.MethodPost, "repos/migrate", payload, &remote)
				}
			} else {
				err = api.Do(ctx, http.MethodPost, "orgs/"+object.Spec.Owner+"/repos", map[string]any{"name": object.Spec.Name, "description": object.Spec.Description}, &remote)
			}
		} else if err == nil {
			err = api.Do(ctx, http.MethodPatch, path, map[string]any{"description": object.Spec.Description, "default_branch": object.Spec.DefaultBranch}, nil)
		}
		if err == nil && len(object.Spec.Topics) > 0 {
			err = api.Do(ctx, http.MethodPut, path+"/topics", map[string]any{"topics": object.Spec.Topics}, nil)
		}
		if err == nil {
			object.Status.RemoteID = fmt.Sprint(remote.ID)
		}
	}
	setStatus(&object.Status, object.Generation, err)
	if updateErr := r.Status().Update(ctx, &object); updateErr != nil {
		return ctrl.Result{}, updateErr
	}
	if err != nil {
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	return ctrl.Result{RequeueAfter: 10 * time.Minute}, nil
}
func (r *RepositoryReconciler) SetupWithManager(m ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(m).For(&forgev1.ForgejoRepository{}).Complete(r)
}

func setStatus(status *forgev1.CommonStatus, generation int64, reconcileErr error) {
	now := metav1.Now()
	status.ObservedGeneration = generation
	status.LastReconciliationTime = &now
	ready, synced, degraded := metav1.ConditionTrue, metav1.ConditionTrue, metav1.ConditionFalse
	reason, message := "Reconciled", "remote resource matches the declared state"
	if reconcileErr != nil {
		ready, synced, degraded = metav1.ConditionFalse, metav1.ConditionFalse, metav1.ConditionTrue
		reason, message = "ReconcileFailed", reconcileErr.Error()
	}
	apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: "Ready", Status: ready, Reason: reason, Message: message, ObservedGeneration: generation})
	apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: "Synced", Status: synced, Reason: reason, Message: message, ObservedGeneration: generation})
	apimeta.SetStatusCondition(&status.Conditions, metav1.Condition{Type: "Degraded", Status: degraded, Reason: reason, Message: message, ObservedGeneration: generation})
}

var _ = finalizer
