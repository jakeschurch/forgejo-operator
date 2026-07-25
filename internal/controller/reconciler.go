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
		path := "repos/" + object.Spec.Owner + "/" + object.Spec.Name
		var remote struct {
			ID int64 `json:"id"`
		}
		err = api.Do(ctx, http.MethodGet, path, nil, &remote)
		var apiErr *forgeapi.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound {
			if object.Spec.Import != nil {
				payload := map[string]any{"clone_addr": object.Spec.Import.CloneURL, "repo_owner": object.Spec.Owner, "repo_name": object.Spec.Name, "description": object.Spec.Description}
				err = api.Do(ctx, http.MethodPost, "repos/migrate", payload, &remote)
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
