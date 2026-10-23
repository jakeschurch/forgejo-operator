package controller

import (
	"context"
	"net/http"
	"strings"
	"testing"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// collaboratorProviderFixture places the ForgejoProvider and its token Secret
// only in providerHome, and a ForgejoCollaborator in objectNamespace that
// names the provider with the given providerNamespace. It records the
// Authorization header of every request that reaches Forgejo.
func collaboratorProviderFixture(providerHome, objectNamespace, providerNamespace string) (*managedReconciler, client.Client, ctrl.Request, *[]string) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = forgev1.AddToScheme(scheme)
	object := &forgev1.ForgejoCollaborator{
		ObjectMeta: metav1.ObjectMeta{Name: "kargo-foundrybox", Namespace: objectNamespace},
		Spec: forgev1.CollaboratorSpec{
			CommonSpec: forgev1.CommonSpec{ProviderRef: "code-jakeschurch", ProviderNamespace: providerNamespace},
			Owner:      "jake", Repository: "foundrybox", Username: "kargo", Permission: "write",
		},
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&forgev1.ForgejoCollaborator{}).
		WithObjects(
			object,
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "forgejo-operator-admin", Namespace: providerHome},
				Data:       map[string][]byte{"token": []byte("admin-token")},
			},
			&forgev1.ForgejoProvider{
				ObjectMeta: metav1.ObjectMeta{Name: "code-jakeschurch", Namespace: providerHome},
				Spec: forgev1.ForgejoProviderSpec{
					URL:            "https://forgejo.invalid",
					TokenSecretRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "forgejo-operator-admin"}, Key: "token"},
				},
			},
		).Build()
	var authorizations []string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		authorizations = append(authorizations, r.Header.Get("Authorization"))
		return response(http.StatusNoContent, ""), nil
	})
	reconciler := &managedReconciler{
		Reconciler: Reconciler{Client: kube, Transport: transport},
		newObject:  func() client.Object { return &forgev1.ForgejoCollaborator{} },
	}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: objectNamespace, Name: object.Name}}
	return reconciler, kube, request, &authorizations
}

func readyCondition(t *testing.T, kube client.Client, request ctrl.Request) *metav1.Condition {
	t.Helper()
	var stored forgev1.ForgejoCollaborator
	if err := kube.Get(context.Background(), request.NamespacedName, &stored); err != nil {
		t.Fatal(err)
	}
	condition := apimeta.FindStatusCondition(stored.Status.Conditions, "Ready")
	if condition == nil {
		t.Fatalf("no Ready condition: %#v", stored.Status.Conditions)
	}
	return condition
}

// Regression: managed kinds (collaborators, robots, access tokens, ...) looked
// the provider up in their own namespace and ignored spec.providerNamespace,
// so a kargo-namespace resource pointing at the forgejo-namespace provider
// failed with `get provider: ... not found`.
func TestManagedReconcileHonoursProviderNamespace(t *testing.T) {
	reconciler, kube, request, authorizations := collaboratorProviderFixture("forgejo", "kargo", "forgejo")
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	condition := readyCondition(t, kube, request)
	if condition.Status != metav1.ConditionTrue || condition.Reason != "Reconciled" {
		t.Fatalf("Ready=%s reason=%s message=%s", condition.Status, condition.Reason, condition.Message)
	}
	if len(*authorizations) == 0 {
		t.Fatal("no request reached Forgejo")
	}
	for _, authorization := range *authorizations {
		if !strings.Contains(authorization, "admin-token") {
			t.Fatalf("request not authenticated with the provider-namespace credential: %q", authorization)
		}
	}
}

func TestManagedReconcileDefaultsProviderToObjectNamespace(t *testing.T) {
	reconciler, kube, request, authorizations := collaboratorProviderFixture("forgejo", "forgejo", "")
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if condition := readyCondition(t, kube, request); condition.Reason != "Reconciled" {
		t.Fatalf("same-namespace provider not resolved: %s", condition.Message)
	}
	if len(*authorizations) == 0 {
		t.Fatal("no request reached Forgejo")
	}
}

func TestManagedReconcileWithoutProviderNamespaceStaysLocal(t *testing.T) {
	reconciler, kube, request, authorizations := collaboratorProviderFixture("forgejo", "kargo", "")
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	condition := readyCondition(t, kube, request)
	if condition.Status != metav1.ConditionFalse || !strings.Contains(condition.Message, "get provider") {
		t.Fatalf("Ready=%s message=%s, want a local provider lookup failure", condition.Status, condition.Message)
	}
	if len(*authorizations) != 0 {
		t.Fatalf("Forgejo called without a resolvable provider: %d requests", len(*authorizations))
	}
}
