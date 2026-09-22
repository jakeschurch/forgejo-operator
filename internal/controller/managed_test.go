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
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
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
		AuthorizationHeader string            `json:"authorization_header"`
		Config              map[string]string `json:"config"`
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
	if id != "4" || method != http.MethodPatch || payload.AuthorizationHeader != "Bearer "+webhookSecret {
		t.Fatalf("webhook adoption did not configure bearer authorization: id=%q method=%s configured=%t", id, method, payload.AuthorizationHeader != "")
	}
	if _, misplaced := payload.Config["authorization_header"]; misplaced {
		t.Fatal("webhook authorization header was misplaced in config")
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

const (
	deployKeyPublic = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g argocd@homelab"
	deployKeyOther  = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMjJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn someone-else"
)

// deployKeyFixture builds a ForgejoDeployKey plus a kube client holding the
// referenced public key Secret.
func deployKeyFixture(readOnly bool, remoteID string) (*forgev1.ForgejoDeployKey, client.Client) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = forgev1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: "forgejo"},
		Data:       map[string][]byte{"publicKey": []byte(deployKeyPublic)},
	}).Build()
	object := &forgev1.ForgejoDeployKey{
		ObjectMeta: metav1.ObjectMeta{Name: "foundrybox-argocd-readonly", Namespace: "forgejo"},
		Spec: forgev1.DeployKeySpec{
			CommonSpec: forgev1.CommonSpec{ProviderRef: "default"},
			Owner:      "foundry-labs", Repository: "foundrybox", Title: "argocd", ReadOnly: readOnly,
			PublicKeySecretRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "key"}, Key: "publicKey"},
		},
		Status: forgev1.CommonStatus{RemoteID: remoteID},
	}
	return object, kube
}

func TestDeployKeyReadOnlyChangeRecreatesRemote(t *testing.T) {
	object, kube := deployKeyFixture(false, "42")
	var requests []string
	var created map[string]any
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys/42"):
			return response(http.StatusOK, `{"id":42,"title":"argocd","key":"`+deployKeyPublic+`","read_only":true}`), nil
		case r.Method == http.MethodDelete:
			return response(http.StatusNoContent, ""), nil
		case r.Method == http.MethodPost:
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				return nil, err
			}
			return response(http.StatusCreated, `{"id":74}`), nil
		}
		return response(http.StatusOK, `[]`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube}}
	id, err := reconciler.reconcile(context.Background(), api, object)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(requests, ",")
	if !strings.Contains(got, "DELETE /api/v1/repos/foundry-labs/foundrybox/keys/42") ||
		!strings.Contains(got, "POST /api/v1/repos/foundry-labs/foundrybox/keys") {
		t.Fatalf("readOnly change did not recreate the remote key: %s", got)
	}
	if created["read_only"] != false || created["title"] != "argocd" {
		t.Fatalf("recreated key did not carry the declared state: %#v", created)
	}
	if id != "74" {
		t.Fatalf("status.remoteID was not advanced to the new key: %q", id)
	}
}

func TestDeployKeyRecreateFailureReportsDegraded(t *testing.T) {
	object, kube := deployKeyFixture(false, "42")
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys/42"):
			return response(http.StatusOK, `{"id":42,"title":"argocd","key":"`+deployKeyPublic+`","read_only":true}`), nil
		case r.Method == http.MethodDelete:
			return response(http.StatusNoContent, ""), nil
		case r.Method == http.MethodPost:
			return response(http.StatusUnprocessableEntity, `{"message":"Key content has been used as non-deploy key"}`), nil
		}
		return response(http.StatusOK, `[]`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube}}
	id, err := reconciler.reconcile(context.Background(), api, object)
	if err == nil {
		t.Fatal("failed recreate reported success")
	}
	if id != "" {
		t.Fatalf("failed recreate returned a remote id: %q", id)
	}
	if strings.Contains(err.Error(), deployKeyPublic) {
		t.Fatalf("error leaks credential: %v", err)
	}
	setStatus(&object.Status, object.Generation, err)
	for _, condition := range object.Status.Conditions {
		want := metav1.ConditionFalse
		if condition.Type == "Degraded" {
			want = metav1.ConditionTrue
		}
		if condition.Status != want {
			t.Fatalf("condition %s is %s, want %s", condition.Type, condition.Status, want)
		}
	}
}

func TestDeployKeyAdoptsKeyMatchingDeclaredState(t *testing.T) {
	object, kube := deployKeyFixture(false, "42")
	var requests []string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/keys/42"):
			return response(http.StatusNotFound, `{"message":"not found"}`), nil
		case strings.HasSuffix(r.URL.Path, "/keys/74"):
			return response(http.StatusOK, `{"id":74,"title":"argocd","key":"`+deployKeyPublic+`","read_only":false}`), nil
		case r.Method == http.MethodGet:
			return response(http.StatusOK, `[{"id":9,"title":"unrelated","key":"`+deployKeyOther+`"},{"id":74,"title":"argocd","key":"`+deployKeyPublic+`"}]`), nil
		}
		return response(http.StatusCreated, `{"id":99}`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube}}
	id, err := reconciler.reconcile(context.Background(), api, object)
	if err != nil {
		t.Fatal(err)
	}
	if id != "74" {
		t.Fatalf("stale remoteID was not repaired by adoption: %q", id)
	}
	got := strings.Join(requests, ",")
	if strings.Contains(got, "DELETE") || strings.Contains(got, "POST") {
		t.Fatalf("adoption of a matching key mutated the remote: %s", got)
	}
}

func TestDeployKeyFingerprintMismatchIsNeverDeleted(t *testing.T) {
	object, kube := deployKeyFixture(false, "42")
	var requests []string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if strings.HasSuffix(r.URL.Path, "/keys/42") {
			return response(http.StatusOK, `{"id":42,"title":"argocd","key":"`+deployKeyOther+`","read_only":true}`), nil
		}
		return response(http.StatusOK, `[]`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube}}
	if _, err := reconciler.reconcile(context.Background(), api, object); err == nil {
		t.Fatal("foreign deploy key reported as reconciled")
	}
	if got := strings.Join(requests, ","); strings.Contains(got, "DELETE") {
		t.Fatalf("foreign deploy key was deleted: %s", got)
	}
}

func TestDeployKeyStaleRemoteIDAdoptsByFingerprint(t *testing.T) {
	object, kube := deployKeyFixture(false, "42")
	var requests []string
	var created map[string]any
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch {
		case strings.HasSuffix(r.URL.Path, "/keys/42"):
			return response(http.StatusNotFound, `{"message":"not found"}`), nil
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys/74"):
			return response(http.StatusOK, `{"id":74,"title":"argocd-old","key":"`+deployKeyPublic+`","read_only":false}`), nil
		case r.Method == http.MethodGet:
			// Nothing carries the declared title: only the fingerprint can
			// locate the key this resource manages.
			return response(http.StatusOK, `[{"id":9,"title":"unrelated","key":"`+deployKeyOther+`"},{"id":74,"title":"argocd-old","key":"`+deployKeyPublic+`"}]`), nil
		case r.Method == http.MethodDelete:
			return response(http.StatusNoContent, ""), nil
		}
		if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
			return nil, err
		}
		return response(http.StatusCreated, `{"id":81}`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube}}
	id, err := reconciler.reconcile(context.Background(), api, object)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(requests, ",")
	if !strings.Contains(got, "GET /api/v1/repos/foundry-labs/foundrybox/keys/42") {
		t.Fatalf("recorded remoteID was never probed: %s", got)
	}
	if !strings.Contains(got, "DELETE /api/v1/repos/foundry-labs/foundrybox/keys/74") ||
		strings.Contains(got, "DELETE /api/v1/repos/foundry-labs/foundrybox/keys/9") ||
		strings.Contains(got, "DELETE /api/v1/repos/foundry-labs/foundrybox/keys/42") {
		t.Fatalf("fingerprint adoption deleted the wrong key: %s", got)
	}
	if created["title"] != "argocd" || created["read_only"] != false || id != "81" {
		t.Fatalf("adopted key was not converged: payload=%#v id=%q", created, id)
	}
}

// deployKeyFixtureWithKey is deployKeyFixture for a declared public key that is
// not the canonical one-line OpenSSH fixture.
func deployKeyFixtureWithKey(publicKey string, readOnly bool, remoteID string) (*forgev1.ForgejoDeployKey, client.Client) {
	object, _ := deployKeyFixture(readOnly, remoteID)
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = forgev1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: "forgejo"},
		Data:       map[string][]byte{"publicKey": []byte(publicKey)},
	}).Build()
	return object, kube
}

// deployKeyReconcileFixture wires a deploy key, its provider and the provider
// credential into a fake client so Reconcile — not just reconcile — can be
// driven end to end against transport.
func deployKeyReconcileFixture(readOnly bool, remoteID string, transport http.RoundTripper) (*managedReconciler, client.Client, ctrl.Request) {
	object, _ := deployKeyFixture(readOnly, remoteID)
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = forgev1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&forgev1.ForgejoDeployKey{}).
		WithObjects(
			object,
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "key", Namespace: "forgejo"},
				Data:       map[string][]byte{"publicKey": []byte(deployKeyPublic)},
			},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "forgejo-token", Namespace: "forgejo"},
				Data:       map[string][]byte{"token": []byte("admin-token")},
			},
			&forgev1.ForgejoProvider{
				ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "forgejo"},
				Spec: forgev1.ForgejoProviderSpec{
					URL:            "https://forgejo.invalid",
					TokenSecretRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "forgejo-token"}, Key: "token"},
				},
			},
		).Build()
	reconciler := &managedReconciler{
		Reconciler: Reconciler{Client: kube, Transport: transport},
		newObject:  func() client.Object { return &forgev1.ForgejoDeployKey{} },
	}
	request := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "forgejo", Name: object.Name}}
	return reconciler, kube, request
}

func reconciledDeployKey(t *testing.T, kube client.Client, request ctrl.Request) *forgev1.ForgejoDeployKey {
	t.Helper()
	var stored forgev1.ForgejoDeployKey
	if err := kube.Get(context.Background(), request.NamespacedName, &stored); err != nil {
		t.Fatal(err)
	}
	return &stored
}

// Blind spot: status.remoteID is written by Reconcile, not by reconcile, so a
// recreate that advances the id is only proven through the full entry point.
func TestDeployKeyReconcileRecordsRecreatedRemoteID(t *testing.T) {
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys/42"):
			return response(http.StatusOK, `{"id":42,"title":"argocd","key":"`+deployKeyPublic+`","read_only":true}`), nil
		case r.Method == http.MethodDelete:
			return response(http.StatusNoContent, ""), nil
		case r.Method == http.MethodPost:
			return response(http.StatusCreated, `{"id":74}`), nil
		}
		return response(http.StatusOK, `[]`), nil
	})
	reconciler, kube, request := deployKeyReconcileFixture(false, "42", transport)
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if got := reconciledDeployKey(t, kube, request).Status.RemoteID; got != "74" {
		t.Fatalf("status.remoteID is %q, want the recreated key 74", got)
	}
}

// Defect 1: a POST that fails for a transient reason must be retried inside the
// reconcile rather than leaving the repository keyless until the next requeue.
func TestDeployKeyRecreateRetriesTransientCreateFailure(t *testing.T) {
	object, kube := deployKeyFixture(false, "42")
	posts := 0
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys/42"):
			return response(http.StatusOK, `{"id":42,"title":"argocd","key":"`+deployKeyPublic+`","read_only":true}`), nil
		case r.Method == http.MethodDelete:
			return response(http.StatusNoContent, ""), nil
		case r.Method == http.MethodPost:
			posts++
			if posts == 1 {
				return response(http.StatusBadGateway, ""), nil
			}
			return response(http.StatusCreated, `{"id":74}`), nil
		}
		return response(http.StatusOK, `[]`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube}}
	id, err := reconciler.reconcile(context.Background(), api, object)
	if err != nil {
		t.Fatalf("transient create failure left the repository keyless: %v (posts=%d)", err, posts)
	}
	if id != "74" || posts != 2 {
		t.Fatalf("id=%q posts=%d, want the create retried once", id, posts)
	}
}

// Defect 1: a terminally failed recreate must say the remote key was deleted and
// not recreated, with its own reason, and must not keep claiming the dead id.
func TestDeployKeyKeylessOutageIsReportedDistinctly(t *testing.T) {
	posts := 0
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys/42"):
			return response(http.StatusOK, `{"id":42,"title":"argocd","key":"`+deployKeyPublic+`","read_only":true}`), nil
		case r.Method == http.MethodDelete:
			return response(http.StatusNoContent, ""), nil
		case r.Method == http.MethodPost:
			posts++
			return response(http.StatusUnprocessableEntity, ""), nil
		}
		return response(http.StatusOK, `[]`), nil
	})
	reconciler, kube, request := deployKeyReconcileFixture(false, "42", transport)
	if _, err := reconciler.Reconcile(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if posts != 1 {
		t.Fatalf("a permanent 422 was retried %d times", posts)
	}
	stored := reconciledDeployKey(t, kube, request)
	if stored.Status.RemoteID != "" {
		t.Fatalf("status.remoteID still claims the deleted key: %q", stored.Status.RemoteID)
	}
	var degraded *metav1.Condition
	for i := range stored.Status.Conditions {
		if stored.Status.Conditions[i].Type == "Degraded" {
			degraded = &stored.Status.Conditions[i]
		}
	}
	if degraded == nil || degraded.Status != metav1.ConditionTrue {
		t.Fatalf("keyless repository is not Degraded: %#v", stored.Status.Conditions)
	}
	if degraded.Reason != "RemoteKeyDeletedNotRecreated" {
		t.Fatalf("keyless window is reported as %q, not a distinct reason", degraded.Reason)
	}
}

// Defect 2: a server that does not round-trip the title byte for byte must not
// be read as divergence — that recreates a live credential on every reconcile.
func TestDeployKeyTitleWhitespaceIsNotDivergence(t *testing.T) {
	object, kube := deployKeyFixture(false, "42")
	var requests []string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys/42"):
			return response(http.StatusOK, `{"id":42,"title":" argocd ","key":"`+deployKeyPublic+`","read_only":false}`), nil
		case r.Method == http.MethodPost:
			return response(http.StatusCreated, `{"id":43}`), nil
		}
		return response(http.StatusNoContent, ``), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube}}
	id, err := reconciler.reconcile(context.Background(), api, object)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(requests, ","); strings.Contains(got, "DELETE") || strings.Contains(got, "POST") {
		t.Fatalf("whitespace in the round-tripped title recreated the key: %s", got)
	}
	if id != "42" {
		t.Fatalf("id=%q, want the existing key", id)
	}
}

// Defect 2: a title the server never returns verbatim must not delete and
// recreate the live credential on every single reconcile, forever.
func TestDeployKeyRecreateLoopIsBounded(t *testing.T) {
	object, kube := deployKeyFixture(false, "42")
	deletes := 0
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys/42"):
			// The server clamps the title, so it never matches the declared one.
			return response(http.StatusOK, `{"id":42,"title":"argo","key":"`+deployKeyPublic+`","read_only":false}`), nil
		case r.Method == http.MethodDelete:
			deletes++
			return response(http.StatusNoContent, ""), nil
		case r.Method == http.MethodPost:
			return response(http.StatusCreated, `{"id":42}`), nil
		}
		return response(http.StatusOK, `[]`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube}}
	var lastErr error
	for i := 0; i < 6; i++ {
		_, lastErr = reconciler.reconcile(context.Background(), api, object)
	}
	if deletes > maxDeployKeyRecreates {
		t.Fatalf("recreate loop deleted the live key %d times", deletes)
	}
	if lastErr == nil {
		t.Fatal("an unconverged recreate loop reported success")
	}
}

// Defect 3: a key living past the first page must be found, not recreated.
func TestDeployKeyListingIsPaginated(t *testing.T) {
	object, kube := deployKeyFixture(false, "")
	var requests []string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys/74"):
			return response(http.StatusOK, `{"id":74,"title":"argocd","key":"`+deployKeyPublic+`","read_only":false}`), nil
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys"):
			// The server clamps limit to two entries per page.
			switch r.URL.Query().Get("page") {
			case "", "1":
				return response(http.StatusOK, `[{"id":9,"title":"a","key":"`+deployKeyOther+`"},{"id":10,"title":"b","key":"`+deployKeyOther+`"}]`), nil
			case "2":
				return response(http.StatusOK, `[{"id":74,"title":"argocd","key":"`+deployKeyPublic+`"},{"id":11,"title":"c","key":"`+deployKeyOther+`"}]`), nil
			}
			return response(http.StatusOK, `[]`), nil
		}
		return response(http.StatusCreated, `{"id":99}`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube}}
	id, err := reconciler.reconcile(context.Background(), api, object)
	if err != nil {
		t.Fatal(err)
	}
	if id != "74" {
		t.Fatalf("id=%q: a key past the first page was treated as absent", id)
	}
	if got := strings.Join(requests, ","); strings.Contains(got, "POST") {
		t.Fatalf("an existing key was duplicated: %s", got)
	}
}

// Defect 4: a create whose response carries no id must not be recorded as a
// reconciled remote id of "0".
func TestDeployKeyCreateWithoutIDIsRejected(t *testing.T) {
	object, kube := deployKeyFixture(false, "")
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			return response(http.StatusCreated, ""), nil
		}
		return response(http.StatusOK, `[]`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube}}
	id, err := reconciler.reconcile(context.Background(), api, object)
	if err == nil {
		t.Fatalf("an id-less create reported success with id %q", id)
	}
	if id != "" {
		t.Fatalf("an id-less create returned id %q", id)
	}
}

// Defect 5: key shapes the fingerprinter cannot parse used to post fine and
// must not become a hard rejection.
func TestDeployKeyUnparsableKeyShapeStillCreates(t *testing.T) {
	const pemKey = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=\n-----END PUBLIC KEY-----\n"
	object, kube := deployKeyFixtureWithKey(pemKey, false, "")
	var posted map[string]any
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
				return nil, err
			}
			return response(http.StatusCreated, `{"id":5}`), nil
		}
		return response(http.StatusOK, `[]`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube}}
	id, err := reconciler.reconcile(context.Background(), api, object)
	if err != nil {
		t.Fatalf("a key shape that used to post is now rejected: %v", err)
	}
	if id != "5" || posted["key"] != pemKey {
		t.Fatalf("id=%q posted=%#v", id, posted)
	}
}
