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
