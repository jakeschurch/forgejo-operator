package controller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	forgeapi "github.com/jakeschurch/forgejo-operator/internal/forgejo"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
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

func TestAccessTokenUsesRobotPassword(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = forgev1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&forgev1.ForgejoRobotAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "argo-workflows", Namespace: "argo"},
			Spec: forgev1.RobotAccountSpec{
				CommonSpec: forgev1.CommonSpec{ProviderRef: "default"},
				Username:   "argo-workflows", PasswordSecretName: "robot-password",
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "robot-password", Namespace: "argo"},
			Data:       map[string][]byte{"password": []byte("sensitive-password")},
		},
	).Build()
	var method, path, username, password string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		method, path = r.Method, r.URL.Path
		username, password, _ = r.BasicAuth()
		return response(http.StatusCreated, `{"id":7,"sha1":"generated-token"}`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	object := &forgev1.ForgejoAccessToken{
		ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "argo"},
		Spec: forgev1.AccessTokenSpec{
			CommonSpec: forgev1.CommonSpec{ProviderRef: "default"},
			Username:   "argo-workflows", Name: "private-flakes", SecretName: "reader-token",
		},
	}
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube}}
	id, err := reconciler.reconcile(context.Background(), api, object)
	if err != nil {
		t.Fatal(err)
	}
	if id != "7" || method != http.MethodPost || path != "/api/v1/users/argo-workflows/tokens" ||
		username != "argo-workflows" || password != "sensitive-password" {
		t.Fatalf("id=%q method=%s path=%s username=%s passwordMatch=%t", id, method, path, username, password == "sensitive-password")
	}
	var secret corev1.Secret
	if err := kube.Get(context.Background(), client.ObjectKey{Namespace: "argo", Name: "reader-token"}, &secret); err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["token"]) != "generated-token" {
		t.Fatal("generated token was not stored")
	}
}

func TestMembershipAddsUserThroughTeam(t *testing.T) {
	var requests []string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodGet {
			return response(http.StatusOK, `{"data":[{"id":9,"name":"flake-readers"}]}`), nil
		}
		return response(http.StatusNoContent, ""), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	object := &forgev1.ForgejoMembership{Spec: forgev1.MembershipSpec{
		CommonSpec:   forgev1.CommonSpec{ProviderRef: "default"},
		Organization: "jakeschurch", Username: "argo-workflows", Teams: []string{"flake-readers"},
	}}
	reconciler := managedReconciler{}
	if _, err := reconciler.reconcile(context.Background(), api, object); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(requests, ",")
	if strings.Contains(got, "/orgs/jakeschurch/members/argo-workflows") ||
		!strings.Contains(got, "PUT /api/v1/teams/9/members/argo-workflows") {
		t.Fatalf("unexpected membership requests: %s", got)
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

func TestWebhookConfiguresBearerAuthorizationOnAdoption(t *testing.T) {
	const webhookSecret = "sensitive-webhook-secret"
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = forgev1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "webhook", Namespace: "forgejo"},
		Data:       map[string][]byte{"secret": []byte(webhookSecret)},
	}).Build()
	var method string
	var payload struct {
		Config map[string]string `json:"config"`
	}
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodGet {
			return response(http.StatusOK, `[{"id":4,"config":{"url":"http://events.invalid"}}]`), nil
		}
		method = r.Method
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			return nil, err
		}
		return response(http.StatusNoContent, ""), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	object := &forgev1.ForgejoWebhook{
		ObjectMeta: metav1.ObjectMeta{Name: "ci", Namespace: "forgejo"},
		Spec: forgev1.WebhookSpec{
			CommonSpec: forgev1.CommonSpec{ProviderRef: "default"},
			Owner:      "jakeschurch", Repository: "harbor-operator", URL: "http://events.invalid",
			SecretRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "webhook"}, Key: "secret"},
		},
	}
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube}}
	id, err := reconciler.reconcile(context.Background(), api, object)
	if err != nil {
		t.Fatal(err)
	}
	if id != "4" || method != http.MethodPatch || payload.Config["authorization_header"] != "Bearer "+webhookSecret {
		t.Fatalf("webhook adoption did not configure bearer authorization: id=%q method=%s configured=%t", id, method, payload.Config["authorization_header"] != "")
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
