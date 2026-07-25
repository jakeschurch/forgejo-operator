package controller

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	forgeapi "github.com/jakeschurch/forgejo-operator/internal/forgejo"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCollaboratorRequest(t *testing.T) {
	var method, path, body string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		method, path = r.Method, r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		return response(http.StatusNoContent, ""), nil
	})
	api, err := forgeapi.New("https://forgejo.invalid", "sensitive", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	if err != nil {
		t.Fatal(err)
	}
	object := &forgev1.ForgejoCollaborator{Spec: forgev1.CollaboratorSpec{
		CommonSpec: forgev1.CommonSpec{ProviderRef: "default"},
		Owner:      "jakeschurch", Repository: "homelab", Username: "robot", Permission: "read",
	}}
	reconciler := managedReconciler{}
	id, err := reconciler.reconcile(context.Background(), api, object)
	if err != nil {
		t.Fatal(err)
	}
	if id != "robot" || method != http.MethodPut || path != "/api/v1/repos/jakeschurch/homelab/collaborators/robot" || !strings.Contains(body, `"permission":"read"`) {
		t.Fatalf("id=%q method=%s path=%s body=%s", id, method, path, body)
	}
}

func TestReferencedDeployKeyNeverAppearsInError(t *testing.T) {
	const publicKey = "ssh-ed25519 AAAA-sensitive-material"
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = forgev1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: "forgejo"},
		Data:       map[string][]byte{"publicKey": []byte(publicKey)},
	}).Build()
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			return response(http.StatusOK, `[]`), nil
		}
		return response(http.StatusBadRequest, `{"message":"bad `+publicKey+`"}`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "token", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	object := &forgev1.ForgejoDeployKey{ObjectMeta: metav1.ObjectMeta{Namespace: "forgejo"}, Spec: forgev1.DeployKeySpec{
		CommonSpec: forgev1.CommonSpec{ProviderRef: "default"}, Owner: "jakeschurch", Repository: "homelab", Title: "argo",
		PublicKeySecretRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "key"}, Key: "publicKey"},
	}}
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube}}
	_, err := reconciler.reconcile(context.Background(), api, object)
	if err == nil || strings.Contains(err.Error(), publicKey) {
		t.Fatalf("error leaks credential: %v", err)
	}
}

func TestDuplicateNaturalKeyRejected(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = forgev1.AddToScheme(scheme)
	first := &forgev1.ForgejoRepository{ObjectMeta: metav1.ObjectMeta{Name: "first", Namespace: "forgejo"}, Spec: forgev1.RepositorySpec{CommonSpec: forgev1.CommonSpec{ProviderRef: "default"}, Owner: "jakeschurch", Name: "homelab"}}
	second := first.DeepCopy()
	second.Name = "second"
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(first, second).Build()
	reconciler := Reconciler{Client: kube}
	err := reconciler.ensureUniqueOwner(context.Background(), first)
	if err == nil || !strings.Contains(err.Error(), "second") {
		t.Fatalf("expected duplicate owner, got %v", err)
	}
}

func TestRepositoryPatchPreservesOmittedFields(t *testing.T) {
	if payload := repositoryPatch(forgev1.RepositorySpec{}); len(payload) != 0 {
		t.Fatalf("omitted fields produced authoritative patch: %#v", payload)
	}
	payload := repositoryPatch(forgev1.RepositorySpec{DefaultBranch: "main", Visibility: "private", Features: map[string]bool{"issues": false}})
	if payload["default_branch"] != "main" || payload["private"] != true || payload["has_issues"] != false {
		t.Fatalf("declared fields missing from patch: %#v", payload)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}
