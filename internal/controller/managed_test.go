package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	"github.com/jakeschurch/forgejo-operator/internal/credentials"
	forgeapi "github.com/jakeschurch/forgejo-operator/internal/forgejo"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
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

func TestRepositoryPatchMergeSettings(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		payload := repositoryPatch(forgev1.RepositorySpec{
			AllowManualMerge: &enabled, AutodetectManualMerge: &enabled,
		})
		if len(payload) != 2 || payload["allow_manual_merge"] != enabled || payload["autodetect_manual_merge"] != enabled {
			t.Fatalf("explicit %v not preserved: %#v", enabled, payload)
		}
	}
}

func TestRepositoryReconcilesSettingsOnCreationAndAdoption(t *testing.T) {
	for _, exists := range []bool{false, true} {
		t.Run(fmt.Sprint("exists=", exists), func(t *testing.T) {
			scheme := runtime.NewScheme()
			_ = corev1.AddToScheme(scheme)
			_ = forgev1.AddToScheme(scheme)
			enabled := true
			object := &forgev1.ForgejoRepository{
				ObjectMeta: metav1.ObjectMeta{Name: "queue", Namespace: "forgejo"},
				Spec:       forgev1.RepositorySpec{CommonSpec: forgev1.CommonSpec{ProviderRef: "default"}, Owner: "owner", Name: "queue", AllowManualMerge: &enabled, AutodetectManualMerge: &enabled},
			}
			kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(object).WithObjects(object,
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "provider-token", Namespace: "forgejo"}, Data: map[string][]byte{"token": []byte("fixture")}},
				&forgev1.ForgejoProvider{ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "forgejo"}, Spec: forgev1.ForgejoProviderSpec{URL: "https://forgejo.invalid", TokenSecretRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "provider-token"}, Key: "token"}}},
			).Build()
			created, patched := false, false
			transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				switch r.Method {
				case http.MethodGet:
					if !exists {
						return response(http.StatusNotFound, `{}`), nil
					}
					return response(http.StatusOK, `{"id":7}`), nil
				case http.MethodPost:
					created = true
					return response(http.StatusCreated, `{"id":7}`), nil
				case http.MethodPatch:
					var payload map[string]any
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Fatal(err)
					}
					patched = payload["allow_manual_merge"] == true && payload["autodetect_manual_merge"] == true
					return response(http.StatusOK, `{"id":7}`), nil
				default:
					t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
					return nil, nil
				}
			})
			r := RepositoryReconciler{Reconciler: Reconciler{Client: kube, Transport: transport}}
			if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: client.ObjectKeyFromObject(object)}); err != nil {
				t.Fatal(err)
			}
			if !patched || created == exists {
				t.Fatalf("exists=%v created=%v patched=%v", exists, created, patched)
			}
			if err := kube.Get(context.Background(), client.ObjectKeyFromObject(object), object); err != nil {
				t.Fatal(err)
			}
			ready := meta.FindStatusCondition(object.Status.Conditions, "Ready")
			if ready == nil || ready.Status != metav1.ConditionTrue {
				t.Fatalf("repository not Ready: %+v", object.Status)
			}
		})
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

// Defect 6: a DELETE that fails must not burn the recreate budget. The live key
// is untouched, so charging a failed DELETE lets a run of transient 5xx wedge a
// perfectly healthy resource for the rest of its generation.
func TestDeployKeyFailedDeleteDoesNotBurnRecreateBudget(t *testing.T) {
	object, kube := deployKeyFixture(false, "42")
	deleteFails := true
	deletes, posts := 0, 0
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/keys/42"):
			return response(http.StatusOK, `{"id":42,"title":"argocd","key":"`+deployKeyPublic+`","read_only":true}`), nil
		case r.Method == http.MethodDelete:
			deletes++
			if deleteFails {
				return response(http.StatusServiceUnavailable, ""), nil
			}
			return response(http.StatusNoContent, ""), nil
		case r.Method == http.MethodPost:
			posts++
			return response(http.StatusCreated, `{"id":74}`), nil
		}
		return response(http.StatusOK, `[]`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube}}

	// More failing reconciles than the budget allows.
	for i := 0; i < maxDeployKeyRecreates+2; i++ {
		if _, err := reconciler.reconcile(context.Background(), api, object); err == nil {
			t.Fatalf("a failed DELETE reported success on attempt %d", i)
		}
	}
	if posts != 0 {
		t.Fatalf("a key was created without its predecessor being deleted (posts=%d)", posts)
	}

	// Forgejo recovers: the recreate must still be allowed to proceed.
	deleteFails = false
	id, err := reconciler.reconcile(context.Background(), api, object)
	if err != nil {
		t.Fatalf("transient DELETE failures permanently exhausted the recreate budget: %v", err)
	}
	if id != "74" || posts != 1 {
		t.Fatalf("id=%q posts=%d deletes=%d, want the recovered recreate to land", id, posts, deletes)
	}
}

// pushMirrorFixture builds a ForgejoPushMirror plus a kube client holding the
// referenced credential Secret.
func pushMirrorFixture(remoteUsername string) (*forgev1.ForgejoPushMirror, client.Client) {
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = forgev1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "mirror-token", Namespace: "forgejo"},
		Data:       map[string][]byte{"token": []byte("ghp-sensitive")},
	}).Build()
	object := &forgev1.ForgejoPushMirror{
		ObjectMeta: metav1.ObjectMeta{Name: "homelab-github", Namespace: "forgejo"},
		Spec: forgev1.PushMirrorSpec{
			CommonSpec:     forgev1.CommonSpec{ProviderRef: "default"},
			Owner:          "jake",
			Repository:     "homelab",
			DestinationURL: "https://github.com/jakeschurch/homelab.git",
			Interval:       "8h0m0s",
			RemoteUsername: remoteUsername,
		},
	}
	object.Spec.CredentialsSecretRef = corev1.SecretKeySelector{
		LocalObjectReference: corev1.LocalObjectReference{Name: "mirror-token"}, Key: "token",
	}
	return object, kube
}

// argocd-tag-updater-4mk: a push mirror created without remote_username is
// stored by Forgejo as "https://:TOKEN@github.com/...". GitHub rejects
// empty-username basic auth, falls back to anonymous, and a private repository
// answers "Repository not found" -- surfaced by git as "Authentication failed".
func TestPushMirrorCreateSendsRemoteUsername(t *testing.T) {
	object, kube := pushMirrorFixture("x-access-token")
	var created map[string]any
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "github.com" {
			return receivePackAdvertisement(nil), nil
		}
		if r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				return nil, err
			}
			return response(http.StatusCreated, `{"remote_name":"remote_mirror_new"}`), nil
		}
		return response(http.StatusOK, `[]`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube, Transport: transport}}
	id, err := reconciler.reconcile(context.Background(), api, object)
	if err != nil {
		t.Fatal(err)
	}
	if id != "remote_mirror_new" {
		t.Fatalf("id=%q, want the created mirror's remote_name", id)
	}
	if created["remote_username"] != "x-access-token" {
		t.Fatalf("create payload did not carry remote_username: %#v", created)
	}
	if created["remote_password"] != "ghp-sensitive" || created["remote_address"] != "https://github.com/jakeschurch/homelab.git" {
		t.Fatalf("create payload lost an existing field: %#v", created)
	}
}

// An undeclared remoteUsername must leave the wire payload exactly as it was,
// so existing mirrors are not disturbed by this change.
func TestPushMirrorCreateOmitsEmptyRemoteUsername(t *testing.T) {
	object, kube := pushMirrorFixture("")
	var created map[string]any
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "github.com" {
			return receivePackAdvertisement(nil), nil
		}
		if r.Method == http.MethodPost {
			if err := json.NewDecoder(r.Body).Decode(&created); err != nil {
				return nil, err
			}
			return response(http.StatusCreated, `{"remote_name":"remote_mirror_new"}`), nil
		}
		return response(http.StatusOK, `[]`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube, Transport: transport}}
	if _, err := reconciler.reconcile(context.Background(), api, object); err != nil {
		t.Fatal(err)
	}
	if _, present := created["remote_username"]; present {
		t.Fatalf("an undeclared remoteUsername was sent anyway: %#v", created)
	}
}

// Adopting an existing mirror (no recorded credential hash) only records the
// hash. The credential the live mirror holds cannot be observed, so the first
// observation is taken as the baseline and nothing is written: recreating a
// mirror arms `git push --mirror`, which deletes every destination ref the
// source lacks (the 2026-09-22 incident, 162 refs destroyed on GitHub).
func TestPushMirrorAdoptRecordsHashWithoutWrites(t *testing.T) {
	object, kube := pushMirrorFixture("x-access-token")
	var requests []string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodGet {
			return response(http.StatusOK, `[{"id":5,"remote_name":"remote_mirror_a","remote_address":"https://github.com/jakeschurch/homelab.git","last_error":"push failed"}]`), nil
		}
		return response(http.StatusCreated, `{"id":9}`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube, Transport: transport}}
	id, err := reconciler.reconcile(context.Background(), api, object)
	if err != nil {
		t.Fatal(err)
	}
	if id != "remote_mirror_a" {
		t.Fatalf("id=%q, want the adopted mirror's remote_name", id)
	}
	if object.Status.CredentialHash != pushMirrorCredentialHash("x-access-token", "ghp-sensitive") {
		t.Fatalf("adoption did not record the credential hash: %q", object.Status.CredentialHash)
	}
	requireReadOnly(t, requests)
}

func requireReadOnly(t *testing.T, requests []string) {
	t.Helper()
	for _, request := range requests {
		if !strings.HasPrefix(request, http.MethodGet+" ") {
			t.Fatalf("a guarded push mirror was written to: %v", requests)
		}
	}
}

func TestPushMirrorCreateRecordsHash(t *testing.T) {
	object, kube := pushMirrorFixture("x-access-token")
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Host == "github.com" {
			return receivePackAdvertisement(nil), nil
		}
		if r.Method == http.MethodPost {
			return response(http.StatusCreated, `{"remote_name":"remote_mirror_new"}`), nil
		}
		return response(http.StatusOK, `[]`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	reconciler := managedReconciler{Reconciler: Reconciler{Client: kube, Transport: transport}}
	if _, err := reconciler.reconcile(context.Background(), api, object); err != nil {
		t.Fatal(err)
	}
	if object.Status.CredentialHash != pushMirrorCredentialHash("x-access-token", "ghp-sensitive") {
		t.Fatalf("creation did not record the credential hash: %q", object.Status.CredentialHash)
	}
}

func TestPushMirrorCredentialHash(t *testing.T) {
	// printf 'x-access-token\0ghp-sensitive' | sha256sum
	const want = "662d01a6ac39fe24db029359370f5fa7ecc9933e8b10af43e9401954dc5ff5ff"
	got := pushMirrorCredentialHash("x-access-token", "ghp-sensitive")
	if got != want {
		t.Fatalf("hash=%s, want %s", got, want)
	}
	if got == pushMirrorCredentialHash("x-access-tokenghp", "-sensitive") ||
		got == pushMirrorCredentialHash("", "ghp-sensitive") {
		t.Fatalf("hash %q does not separate username from credential", got)
	}
}

const (
	mirrorOID1 = "1111111111111111111111111111111111111111"
	mirrorOID2 = "2222222222222222222222222222222222222222"
	mirrorOID3 = "3333333333333333333333333333333333333333"
	mirrorTag  = "4444444444444444444444444444444444444444"
	mirrorGone = "9999999999999999999999999999999999999999"
)

// mirrorWorld fakes both sides of a push mirror: the Forgejo API (source) and
// the destination's smart-HTTP ref advertisement.
type mirrorWorld struct {
	lastError string
	// destination refs advertised by receive-pack, name -> oid
	destination map[string]string
	// source refs returned by GET git/refs, name -> oid
	source map[string]string
	// objects Forgejo holds that are not ref tips
	commits, tags map[string]bool
	requests      []string
	destAuthUser  string
	destAuthPass  string
	createPayload map[string]any
	// destinationStatus, when set, is returned instead of an advertisement.
	destinationStatus int
	// noMirror makes Forgejo list no push mirror, so the reconcile creates one.
	noMirror bool
	// listStatus, when set, is returned instead of the push mirror listing.
	listStatus int
}

func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

// receivePackAdvertisement is a smart-HTTP receive-pack ref advertisement of
// refs (name -> oid). No refs is an empty repository.
func receivePackAdvertisement(refs map[string]string) *http.Response {
	names := make([]string, 0, len(refs))
	for name := range refs {
		names = append(names, name)
	}
	sort.Strings(names)
	body := pkt("# service=git-receive-pack\n") + "0000"
	if len(names) == 0 {
		body += pkt(strings.Repeat("0", 40) + " capabilities^{}\x00report-status delete-refs ofs-delta\n")
	}
	for i, name := range names {
		line := refs[name] + " " + name
		if i == 0 {
			line += "\x00report-status delete-refs ofs-delta"
		}
		body += pkt(line + "\n")
	}
	body += "0000"
	resp := response(http.StatusOK, body)
	resp.Header.Set("Content-Type", "application/x-git-receive-pack-advertisement")
	return resp
}

func (w *mirrorWorld) transport() roundTripFunc {
	return func(r *http.Request) (*http.Response, error) {
		w.requests = append(w.requests, r.Method+" "+r.URL.Path)
		if r.URL.Host == "github.com" {
			if r.URL.Path != "/jakeschurch/homelab.git/info/refs" || r.URL.Query().Get("service") != "git-receive-pack" {
				return response(http.StatusNotFound, ""), nil
			}
			w.destAuthUser, w.destAuthPass, _ = r.BasicAuth()
			if w.destinationStatus != 0 {
				return response(w.destinationStatus, ""), nil
			}
			return receivePackAdvertisement(w.destination), nil
		}
		const repo = "/api/v1/repos/jake/homelab"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == repo+"/push_mirrors":
			if w.listStatus != 0 {
				return response(w.listStatus, ""), nil
			}
			if w.noMirror {
				return response(http.StatusOK, `[]`), nil
			}
			lastError, _ := json.Marshal(w.lastError)
			return response(http.StatusOK, `[{"remote_name":"remote_mirror_old","remote_address":"https://github.com/jakeschurch/homelab.git","last_error":`+string(lastError)+`}]`), nil
		case r.Method == http.MethodGet && r.URL.Path == repo+"/git/refs":
			type ref struct {
				Ref    string            `json:"ref"`
				Object map[string]string `json:"object"`
			}
			var refs []ref
			for name, oid := range w.source {
				refs = append(refs, ref{Ref: name, Object: map[string]string{"sha": oid, "type": "commit"}})
			}
			raw, _ := json.Marshal(refs)
			return response(http.StatusOK, string(raw)), nil
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, repo+"/git/commits/"):
			if w.commits[strings.TrimPrefix(r.URL.Path, repo+"/git/commits/")] {
				return response(http.StatusOK, `{}`), nil
			}
			return response(http.StatusNotFound, ""), nil
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, repo+"/git/tags/"):
			if w.tags[strings.TrimPrefix(r.URL.Path, repo+"/git/tags/")] {
				return response(http.StatusOK, `{}`), nil
			}
			return response(http.StatusBadRequest, ""), nil
		case r.Method == http.MethodDelete && r.URL.Path == repo+"/push_mirrors/remote_mirror_old":
			return response(http.StatusNoContent, ""), nil
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, repo+"/push_mirrors/"):
			// What Forgejo answers for a name that is not a mirror, such as
			// the legacy "0": a 404 the delete path treats as already gone.
			return response(http.StatusNotFound, ""), nil
		case r.Method == http.MethodPost && r.URL.Path == repo+"/push_mirrors":
			if err := json.NewDecoder(r.Body).Decode(&w.createPayload); err != nil {
				return nil, err
			}
			// Forgejo's push mirror objects carry no numeric id.
			return response(http.StatusCreated, `{"remote_name":"remote_mirror_new","remote_address":"https://github.com/jakeschurch/homelab.git"}`), nil
		case r.Method == http.MethodPost && r.URL.Path == repo+"/push_mirrors-sync":
			return response(http.StatusOK, ""), nil
		}
		return response(http.StatusTeapot, ""), nil
	}
}

// writes returns every non-GET request the operator sent to Forgejo.
func (w *mirrorWorld) writes() []string {
	var out []string
	for _, request := range w.requests {
		if !strings.HasPrefix(request, http.MethodGet+" ") {
			out = append(out, request)
		}
	}
	return out
}

// cleanMirrorWorld is a destination that is safe to mirror over: every ref
// exists in Forgejo, and the stale branch's older object is in Forgejo's
// history. Forgejo being ahead is normal.
func cleanMirrorWorld() *mirrorWorld {
	return &mirrorWorld{
		destination: map[string]string{
			"refs/heads/main":  mirrorOID1,
			"refs/heads/stale": mirrorOID2,
			"refs/tags/v1":     mirrorTag,
		},
		source: map[string]string{
			"refs/heads/main":    mirrorOID1,
			"refs/heads/stale":   mirrorOID3,
			"refs/heads/feature": mirrorOID3,
			"refs/tags/v1":       mirrorTag,
			"refs/pull/1/head":   mirrorOID3,
		},
		commits: map[string]bool{mirrorOID1: true, mirrorOID2: true, mirrorOID3: true},
		tags:    map[string]bool{mirrorTag: true},
	}
}

// runPushMirrorReconcile drives the full Reconcile (so conditions are set the
// way production sets them) for a mirror whose recorded hash is storedHash,
// while the Secret holds "ghp-sensitive".
func runPushMirrorReconcile(t *testing.T, storedHash string, world *mirrorWorld) (forgev1.ForgejoPushMirror, ctrl.Result) {
	t.Helper()
	return runPushMirrorReconcileWith(t, world, func(object *forgev1.ForgejoPushMirror) {
		object.Status.CredentialHash = storedHash
		object.Status.RemoteID = "remote_mirror_old"
	})
}

// runPushMirrorReconcileWith is runPushMirrorReconcile with the stored object
// shaped by mutate. A deleted object is returned zero-valued once its
// finalizer is gone.
func runPushMirrorReconcileWith(t *testing.T, world *mirrorWorld, mutate func(*forgev1.ForgejoPushMirror)) (forgev1.ForgejoPushMirror, ctrl.Result) {
	t.Helper()
	object, _ := pushMirrorFixture("x-access-token")
	mutate(object)
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = forgev1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&forgev1.ForgejoPushMirror{}).
		WithObjects(object,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "mirror-token", Namespace: "forgejo"}, Data: map[string][]byte{"token": []byte("ghp-sensitive")}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "admin-token", Namespace: "forgejo"}, Data: map[string][]byte{"token": []byte("admin")}},
			&forgev1.ForgejoProvider{
				ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "forgejo"},
				Spec: forgev1.ForgejoProviderSpec{
					URL:            "https://forgejo.invalid",
					TokenSecretRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "admin-token"}, Key: "token"},
				},
			}).Build()
	r := &managedReconciler{
		Reconciler: Reconciler{Client: kube, Transport: world.transport()},
		newObject:  func() client.Object { return &forgev1.ForgejoPushMirror{} },
	}
	key := client.ObjectKey{Namespace: "forgejo", Name: "homelab-github"}
	result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatal(err)
	}
	var stored forgev1.ForgejoPushMirror
	if err := kube.Get(context.Background(), key, &stored); err != nil && !apierrors.IsNotFound(err) {
		t.Fatal(err)
	}
	return stored, result
}

var (
	newMirrorHash = pushMirrorCredentialHash("x-access-token", "ghp-sensitive")
	oldMirrorHash = pushMirrorCredentialHash("x-access-token", "ghp-expired")
)

func TestPushMirrorUnchangedHashDoesNothing(t *testing.T) {
	world := cleanMirrorWorld()
	stored, _ := runPushMirrorReconcile(t, newMirrorHash, world)
	if writes := world.writes(); len(writes) != 0 {
		t.Fatalf("an unchanged credential wrote to Forgejo: %v", writes)
	}
	for _, request := range world.requests {
		if strings.Contains(request, "/info/refs") || strings.Contains(request, "/git/") {
			t.Fatalf("an unchanged credential ran the rotation guard: %v", world.requests)
		}
	}
	if stored.Status.CredentialHash != newMirrorHash {
		t.Fatalf("hash=%q", stored.Status.CredentialHash)
	}
	if degraded := meta.FindStatusCondition(stored.Status.Conditions, "Degraded"); degraded == nil || degraded.Status != metav1.ConditionFalse {
		t.Fatalf("degraded=%+v", degraded)
	}
}

func TestPushMirrorRotatesWhenGuardIsClean(t *testing.T) {
	world := cleanMirrorWorld()
	stored, _ := runPushMirrorReconcile(t, oldMirrorHash, world)
	want := []string{
		"DELETE /api/v1/repos/jake/homelab/push_mirrors/remote_mirror_old",
		"POST /api/v1/repos/jake/homelab/push_mirrors",
		"POST /api/v1/repos/jake/homelab/push_mirrors-sync",
	}
	if got := world.writes(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("writes=%v, want %v", got, want)
	}
	if world.destAuthUser != "x-access-token" || world.destAuthPass != "ghp-sensitive" {
		t.Fatalf("destination refs were not read with the NEW credential (user=%q, passwordMatch=%t)", world.destAuthUser, world.destAuthPass == "ghp-sensitive")
	}
	if world.createPayload["remote_username"] != "x-access-token" || world.createPayload["remote_password"] != "ghp-sensitive" ||
		world.createPayload["remote_address"] != "https://github.com/jakeschurch/homelab.git" || world.createPayload["sync_on_commit"] != false {
		t.Fatalf("recreate payload differs from creation: %#v", world.createPayload)
	}
	if stored.Status.CredentialHash != newMirrorHash || stored.Status.RemoteID != "remote_mirror_new" {
		t.Fatalf("hash=%q remoteID=%q after rotation", stored.Status.CredentialHash, stored.Status.RemoteID)
	}
	if degraded := meta.FindStatusCondition(stored.Status.Conditions, "Degraded"); degraded == nil || degraded.Status != metav1.ConditionFalse {
		t.Fatalf("degraded=%+v", degraded)
	}
}

// requireBlocked asserts the rotation was refused: nothing written, the old
// hash kept so the next reconcile retries, Degraded with reason, and requeued.
func requireBlocked(t *testing.T, world *mirrorWorld, stored forgev1.ForgejoPushMirror, result ctrl.Result, reason string, mentions ...string) {
	t.Helper()
	if writes := world.writes(); len(writes) != 0 {
		t.Fatalf("a blocked rotation wrote to Forgejo: %v", writes)
	}
	if stored.Status.CredentialHash != oldMirrorHash {
		t.Fatalf("a blocked rotation recorded the new hash, so it would never retry")
	}
	degraded := meta.FindStatusCondition(stored.Status.Conditions, "Degraded")
	if degraded == nil || degraded.Status != metav1.ConditionTrue || degraded.Reason != reason {
		t.Fatalf("degraded=%+v, want True/%s", degraded, reason)
	}
	for _, mention := range mentions {
		if !strings.Contains(degraded.Message, mention) {
			t.Fatalf("Degraded message %q does not name %q", degraded.Message, mention)
		}
	}
	if strings.Contains(degraded.Message, "ghp-sensitive") {
		t.Fatal("Degraded message leaks the credential")
	}
	if result.RequeueAfter == 0 {
		t.Fatal("a blocked rotation must be retried")
	}
}

func TestPushMirrorRotationBlockedWhenLastSyncFailed(t *testing.T) {
	world := cleanMirrorWorld()
	world.lastError = "push failed: fatal: Authentication failed"
	stored, result := runPushMirrorReconcile(t, oldMirrorHash, world)
	requireBlocked(t, world, stored, result, reasonMirrorSyncFailing)
}

func TestPushMirrorRotationBlockedWhenDestinationObjectMissingFromSource(t *testing.T) {
	world := cleanMirrorWorld()
	// Someone pushed straight to GitHub: the ref exists in Forgejo, but the
	// destination's tip is a commit Forgejo has never seen. The mirror push
	// would force it back and lose that commit.
	world.destination["refs/heads/main"] = mirrorGone
	stored, result := runPushMirrorReconcile(t, oldMirrorHash, world)
	requireBlocked(t, world, stored, result, reasonDestinationHasObjectsMissingFromSource, "refs/heads/main")
}

func TestPushMirrorRotationBlockedWhenDestinationRefMissingFromSource(t *testing.T) {
	world := cleanMirrorWorld()
	// The 2026-09-22 shape: refs that only exist on GitHub.
	world.destination["refs/heads/only-on-github"] = mirrorOID1
	world.destination["refs/tags/only-on-github"] = mirrorOID2
	stored, result := runPushMirrorReconcile(t, oldMirrorHash, world)
	requireBlocked(t, world, stored, result, reasonDestinationHasRefsMissingFromSource,
		"refs/heads/only-on-github", "refs/tags/only-on-github")
}

// A destination that refuses the new credential is not evidence of safety.
func TestPushMirrorRotationBlockedWhenDestinationUnreadable(t *testing.T) {
	world := cleanMirrorWorld()
	world.destinationStatus = http.StatusUnauthorized
	stored, result := runPushMirrorReconcile(t, oldMirrorHash, world)
	requireBlocked(t, world, stored, result, reasonDestinationRefsUnreadable, "401")
}

// argocd-tag-updater-cnu: creating a mirror arms the same `git push --mirror`
// a rotation does, so creation is guarded too.

// runPushMirrorCreate reconciles an object with no recorded mirror against a
// Forgejo that lists none, so the reconcile takes the create path.
func runPushMirrorCreate(t *testing.T, world *mirrorWorld) (forgev1.ForgejoPushMirror, ctrl.Result) {
	t.Helper()
	world.noMirror = true
	return runPushMirrorReconcileWith(t, world, func(*forgev1.ForgejoPushMirror) {})
}

// requireCreateBlocked asserts the create was refused: nothing written (above
// all, no POST that would arm a mirror push), no hash or id recorded, Degraded
// with reason, and requeued.
func requireCreateBlocked(t *testing.T, world *mirrorWorld, stored forgev1.ForgejoPushMirror, result ctrl.Result, reason string, mentions ...string) {
	t.Helper()
	if writes := world.writes(); len(writes) != 0 {
		t.Fatalf("a blocked create wrote to Forgejo: %v", writes)
	}
	if stored.Status.CredentialHash != "" || stored.Status.RemoteID != "" {
		t.Fatalf("a blocked create recorded hash=%q remoteID=%q", stored.Status.CredentialHash, stored.Status.RemoteID)
	}
	degraded := meta.FindStatusCondition(stored.Status.Conditions, "Degraded")
	if degraded == nil || degraded.Status != metav1.ConditionTrue || degraded.Reason != reason {
		t.Fatalf("degraded=%+v, want True/%s", degraded, reason)
	}
	if !strings.Contains(degraded.Message, "creation is blocked") {
		t.Fatalf("Degraded message %q does not say creation was blocked", degraded.Message)
	}
	for _, mention := range mentions {
		if !strings.Contains(degraded.Message, mention) {
			t.Fatalf("Degraded message %q does not name %q", degraded.Message, mention)
		}
	}
	if strings.Contains(degraded.Message, "ghp-sensitive") {
		t.Fatal("Degraded message leaks the credential")
	}
	if result.RequeueAfter == 0 {
		t.Fatal("a blocked create must be retried")
	}
}

// requireCreated asserts the mirror was created with the declared credential
// after the destination was read with it, and its remote_name recorded.
func requireCreated(t *testing.T, world *mirrorWorld, stored forgev1.ForgejoPushMirror) {
	t.Helper()
	want := []string{"POST /api/v1/repos/jake/homelab/push_mirrors"}
	if got := world.writes(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("writes=%v, want %v", got, want)
	}
	if world.destAuthUser != "x-access-token" || world.destAuthPass != "ghp-sensitive" {
		t.Fatal("destination refs were not read with the mirror's credential before creating it")
	}
	if stored.Status.CredentialHash != newMirrorHash || stored.Status.RemoteID != "remote_mirror_new" {
		t.Fatalf("hash=%q remoteID=%q after create", stored.Status.CredentialHash, stored.Status.RemoteID)
	}
	if degraded := meta.FindStatusCondition(stored.Status.Conditions, "Degraded"); degraded == nil || degraded.Status != metav1.ConditionFalse {
		t.Fatalf("degraded=%+v", degraded)
	}
}

// The 2026-09-22 shape on the create path: refs that only exist on GitHub.
func TestPushMirrorCreateBlockedWhenDestinationRefMissingFromSource(t *testing.T) {
	world := cleanMirrorWorld()
	world.destination["refs/heads/only-on-github"] = mirrorOID1
	stored, result := runPushMirrorCreate(t, world)
	requireCreateBlocked(t, world, stored, result, reasonDestinationHasRefsMissingFromSource, "refs/heads/only-on-github")
}

func TestPushMirrorCreateBlockedWhenDestinationObjectMissingFromSource(t *testing.T) {
	world := cleanMirrorWorld()
	world.destination["refs/heads/main"] = mirrorGone
	stored, result := runPushMirrorCreate(t, world)
	requireCreateBlocked(t, world, stored, result, reasonDestinationHasObjectsMissingFromSource, "refs/heads/main")
}

// An unreadable destination is not evidence of safety, whatever the status.
func TestPushMirrorCreateBlockedWhenDestinationUnreadable(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusNotFound} {
		world := cleanMirrorWorld()
		world.destinationStatus = status
		stored, result := runPushMirrorCreate(t, world)
		requireCreateBlocked(t, world, stored, result, reasonDestinationRefsUnreadable, strconv.Itoa(status))
	}
}

func TestPushMirrorCreateAllowedForEmptyDestination(t *testing.T) {
	world := cleanMirrorWorld()
	world.destination = map[string]string{}
	stored, _ := runPushMirrorCreate(t, world)
	requireCreated(t, world, stored)
}

// A destination behind Forgejo (a stale branch whose older commit Forgejo
// holds) loses nothing to the mirror push.
func TestPushMirrorCreateAllowedForSubsetDestination(t *testing.T) {
	world := cleanMirrorWorld()
	stored, _ := runPushMirrorCreate(t, world)
	requireCreated(t, world, stored)
}

// argocd-tag-updater-zm3g.16: Forgejo's push mirror listing has no id, so
// remoteID was stored as "0". The next reconcile records the remote_name it
// finds by destination URL, writing nothing to Forgejo -- even when a
// rotation is due and blocked.
func TestPushMirrorLegacyRemoteIDMigratesToRemoteName(t *testing.T) {
	for _, tc := range []struct {
		name, hash string
		blocked    bool
	}{
		{"unchanged credential", newMirrorHash, false},
		{"adoption", "", false},
		{"rotation blocked", oldMirrorHash, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, legacy := range []string{"0", ""} {
				world := cleanMirrorWorld()
				if tc.blocked {
					world.lastError = "push failed"
				}
				stored, _ := runPushMirrorReconcileWith(t, world, func(object *forgev1.ForgejoPushMirror) {
					object.Status.CredentialHash = tc.hash
					object.Status.RemoteID = legacy
				})
				if stored.Status.RemoteID != "remote_mirror_old" {
					t.Fatalf("remoteID %q migrated to %q, want remote_mirror_old", legacy, stored.Status.RemoteID)
				}
				requireReadOnly(t, world.requests)
			}
		})
	}
}

// deletionPolicy: Delete must delete the mirror by its remote_name. A legacy
// remoteID "0" is resolved by destination URL first; DELETE push_mirrors/0
// would 404, be taken as success, and drop the finalizer with the mirror alive.
func TestPushMirrorDeleteUsesRemoteName(t *testing.T) {
	for _, remoteID := range []string{"remote_mirror_old", "0"} {
		world := cleanMirrorWorld()
		stored, _ := runPushMirrorReconcileWith(t, world, func(object *forgev1.ForgejoPushMirror) {
			now := metav1.Now()
			object.Spec.DeletionPolicy = forgev1.DeletionPolicyDelete
			object.Finalizers = []string{finalizer}
			object.DeletionTimestamp = &now
			object.Status.CredentialHash = newMirrorHash
			object.Status.RemoteID = remoteID
		})
		want := []string{"DELETE /api/v1/repos/jake/homelab/push_mirrors/remote_mirror_old"}
		if got := world.writes(); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("remoteID %q: writes=%v, want %v", remoteID, got, want)
		}
		if contains(stored.Finalizers, finalizer) {
			t.Fatalf("remoteID %q: finalizer kept after a successful delete", remoteID)
		}
	}
}

// A legacy remoteID that cannot be resolved (the listing fails) must keep the
// finalizer: dropping it would leave the mirror running with no owner.
func TestPushMirrorDeleteKeepsFinalizerWhenLookupFails(t *testing.T) {
	world := cleanMirrorWorld()
	world.listStatus = http.StatusInternalServerError
	stored, result := runPushMirrorReconcileWith(t, world, func(object *forgev1.ForgejoPushMirror) {
		now := metav1.Now()
		object.Spec.DeletionPolicy = forgev1.DeletionPolicyDelete
		object.Finalizers = []string{finalizer}
		object.DeletionTimestamp = &now
		object.Status.RemoteID = "0"
	})
	if writes := world.writes(); len(writes) != 0 {
		t.Fatalf("an unresolved mirror was written to: %v", writes)
	}
	if !contains(stored.Finalizers, finalizer) || result.RequeueAfter == 0 {
		t.Fatalf("finalizers=%v requeue=%v: a failed lookup must keep the finalizer and retry", stored.Finalizers, result.RequeueAfter)
	}
}

// A mirror already gone (404 for its real name) is a successful delete.
func TestPushMirrorDeleteOfMissingMirrorSucceeds(t *testing.T) {
	world := cleanMirrorWorld()
	world.noMirror = true
	stored, _ := runPushMirrorReconcileWith(t, world, func(object *forgev1.ForgejoPushMirror) {
		now := metav1.Now()
		object.Spec.DeletionPolicy = forgev1.DeletionPolicyDelete
		object.Finalizers = []string{finalizer}
		object.DeletionTimestamp = &now
		object.Status.RemoteID = "remote_mirror_gone"
	})
	want := []string{"DELETE /api/v1/repos/jake/homelab/push_mirrors/remote_mirror_gone"}
	if got := world.writes(); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("writes=%v, want %v", got, want)
	}
	if contains(stored.Finalizers, finalizer) {
		t.Fatal("finalizer kept after the mirror was already gone")
	}
}

const (
	humanAdminUser     = "mint-admin"
	humanAdminPassword = "sensitive-admin-password"
	humanMintedToken   = "generated-human-token"
)

func humanProvider(allowed ...string) *forgev1.ForgejoProvider {
	provider := &forgev1.ForgejoProvider{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "forgejo"},
		Spec:       forgev1.ForgejoProviderSpec{URL: "https://forgejo.invalid"},
	}
	if allowed != nil {
		provider.Spec.HumanAccessTokens = &forgev1.HumanAccessTokenPolicy{
			AllowedUsernames:          allowed,
			AdminCredentialsSecretRef: corev1.LocalObjectReference{Name: "mint-admin"},
		}
	}
	return provider
}

func humanAdminSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "mint-admin", Namespace: "forgejo"},
		Data:       map[string][]byte{"username": []byte(humanAdminUser), "password": []byte(humanAdminPassword)},
	}
}

func humanToken(accountType forgev1.AccessTokenAccountType, username string) *forgev1.ForgejoAccessToken {
	return &forgev1.ForgejoAccessToken{
		TypeMeta:   metav1.TypeMeta{Kind: "ForgejoAccessToken"},
		ObjectMeta: metav1.ObjectMeta{Name: "workstation", Namespace: "forgejo"},
		Spec: forgev1.AccessTokenSpec{
			CommonSpec:  forgev1.CommonSpec{ProviderRef: "default"},
			AccountType: accountType,
			Username:    username, Name: "jake-workstation", Scopes: []string{"write:repository"}, SecretName: "workstation-token",
		},
	}
}

type humanRequest struct {
	method, path, user string
	adminAuth          bool
	body               string
}

// humanHarness records every request. Every POST mints token id 42.
func humanHarness(t *testing.T, objects ...client.Object) (*managedReconciler, *forgeapi.Client, *[]humanRequest) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = forgev1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	var requests []humanRequest
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		user, password, _ := r.BasicAuth()
		var body string
		if r.Body != nil {
			raw, _ := io.ReadAll(r.Body)
			body = string(raw)
		}
		requests = append(requests, humanRequest{r.Method, r.URL.Path, user, user == humanAdminUser && password == humanAdminPassword, body})
		if r.Method == http.MethodDelete {
			return response(http.StatusNoContent, ""), nil
		}
		return response(http.StatusCreated, `{"id":42,"sha1":"`+humanMintedToken+`"}`), nil
	})
	api, err := forgeapi.New("https://forgejo.invalid", "admin-api-token", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	if err != nil {
		t.Fatal(err)
	}
	return &managedReconciler{Reconciler: Reconciler{Client: kube}}, api, &requests
}

func TestHumanAccessTokenMintsWithAdminBasicAuth(t *testing.T) {
	r, api, requests := humanHarness(t, humanProvider("jake"), humanAdminSecret())
	id, err := r.reconcile(context.Background(), api, humanToken(forgev1.AccessTokenAccountHuman, "jake"))
	if err != nil {
		t.Fatal(err)
	}
	if id != "42" || len(*requests) != 1 {
		t.Fatalf("id=%q requests=%d", id, len(*requests))
	}
	got := (*requests)[0]
	if got.method != http.MethodPost || got.path != "/api/v1/users/jake/tokens" || !got.adminAuth ||
		!strings.Contains(got.body, `"name":"jake-workstation"`) || !strings.Contains(got.body, `"write:repository"`) {
		t.Fatalf("method=%s path=%s user=%s adminAuth=%t", got.method, got.path, got.user, got.adminAuth)
	}
	var secret corev1.Secret
	if err := r.Get(context.Background(), client.ObjectKey{Namespace: "forgejo", Name: "workstation-token"}, &secret); err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["token"]) != humanMintedToken {
		t.Fatal("generated token was not stored")
	}
}

// A human must never be reachable through an account-altering endpoint: the only
// requests the human path may ever make are creating and deleting tokens.
func TestHumanAccessTokenNeverTouchesTheAccount(t *testing.T) {
	object := humanToken(forgev1.AccessTokenAccountHuman, "jake")
	object.Spec.RotationNonce = "2"
	object.Status.RemoteID = "41"
	r, api, requests := humanHarness(t, humanProvider("jake"), humanAdminSecret(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "workstation-token", Namespace: "forgejo", Annotations: map[string]string{credentials.RotationNonceAnnotation: "1"}},
		Data:       map[string][]byte{"token": []byte("old")},
	})
	if _, err := r.reconcile(context.Background(), api, object); err != nil {
		t.Fatal(err)
	}
	object.Status.RemoteID = "42"
	if err := r.deleteRemote(context.Background(), api, object, "42"); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, request := range *requests {
		got = append(got, request.method+" "+request.path)
		if !request.adminAuth || strings.Contains(request.body, "password") {
			t.Fatalf("%s %s adminAuth=%t", request.method, request.path, request.adminAuth)
		}
	}
	want := "DELETE /api/v1/users/jake/tokens/41,POST /api/v1/users/jake/tokens,DELETE /api/v1/users/jake/tokens/42"
	if strings.Join(got, ",") != want {
		t.Fatalf("requests: %s", strings.Join(got, ","))
	}
}

// Every refusal must happen before the administrator credential is read (no
// Secret exists here) and before any request reaches Forgejo.
func TestHumanAccessTokenRefusals(t *testing.T) {
	robot := &forgev1.ForgejoRobotAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "ci", Namespace: "forgejo"},
		Spec:       forgev1.RobotAccountSpec{CommonSpec: forgev1.CommonSpec{ProviderRef: "default"}, Username: "ci"},
	}
	otherNamespace := humanToken(forgev1.AccessTokenAccountHuman, "jake")
	otherNamespace.Spec.ProviderNamespace = "elsewhere"
	noScopes := humanToken(forgev1.AccessTokenAccountHuman, "jake")
	noScopes.Spec.Scopes = nil
	for name, tc := range map[string]struct {
		provider *forgev1.ForgejoProvider
		extra    []client.Object
		object   *forgev1.ForgejoAccessToken
		want     string
	}{
		"robot type on a human, allowlisted": {humanProvider("jake"), nil, humanToken(forgev1.AccessTokenAccountRobot, "jake"), "must reference a managed robot account"},
		"unset type on a human, allowlisted": {humanProvider("jake"), nil, humanToken("", "jake"), "must reference a managed robot account"},
		"provider has no policy":             {humanProvider(), nil, humanToken(forgev1.AccessTokenAccountHuman, "jake"), "does not enable humanAccessTokens"},
		"username not allowlisted":           {humanProvider("jake"), nil, humanToken(forgev1.AccessTokenAccountHuman, "margo"), "allowedUsernames"},
		"allowlist match is exact":           {humanProvider("jake"), nil, humanToken(forgev1.AccessTokenAccountHuman, "Jake"), "allowedUsernames"},
		"username is a managed robot":        {humanProvider("ci"), []client.Object{robot}, humanToken(forgev1.AccessTokenAccountHuman, "ci"), "managed robot account"},
		"provider in another namespace":      {humanProvider("jake"), nil, otherNamespace, "same namespace"},
		"no scopes":                          {humanProvider("jake"), nil, noScopes, "at least one scope"},
	} {
		t.Run(name, func(t *testing.T) {
			r, api, requests := humanHarness(t, append(tc.extra, tc.provider)...)
			_, err := r.reconcile(context.Background(), api, tc.object)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v", err)
			}
			if len(*requests) != 0 {
				t.Fatalf("made %d requests", len(*requests))
			}
		})
	}
}

func TestHumanAccessTokenIsNoOpWhenStored(t *testing.T) {
	object := humanToken(forgev1.AccessTokenAccountHuman, "jake")
	object.Status.RemoteID = "42"
	r, api, requests := humanHarness(t, humanProvider("jake"), humanAdminSecret(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "workstation-token", Namespace: "forgejo", Annotations: map[string]string{credentials.RotationNonceAnnotation: ""}},
		Data:       map[string][]byte{"token": []byte("stored")},
	})
	id, err := r.reconcile(context.Background(), api, object)
	if err != nil {
		t.Fatal(err)
	}
	if id != "42" || len(*requests) != 0 {
		t.Fatalf("id=%q requests=%v", id, *requests)
	}
}

func TestHumanAccessTokenRemovedFromAllowlistDegrades(t *testing.T) {
	object := humanToken(forgev1.AccessTokenAccountHuman, "jake")
	stored := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "workstation-token", Namespace: "forgejo", Annotations: map[string]string{credentials.RotationNonceAnnotation: ""}},
		Data:       map[string][]byte{"token": []byte("stored")},
	}
	r, api, requests := humanHarness(t, humanProvider("margo"), humanAdminSecret(), stored)
	if _, err := r.reconcile(context.Background(), api, object); err == nil || !strings.Contains(err.Error(), "allowedUsernames") {
		t.Fatalf("err=%v", err)
	}
	if len(*requests) != 0 {
		t.Fatalf("requests=%v", *requests)
	}
}

func TestHumanAccessTokenRefusesUnrelatedSecret(t *testing.T) {
	r, api, requests := humanHarness(t, humanProvider("jake"), humanAdminSecret(), &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "workstation-token", Namespace: "forgejo"},
		Data:       map[string][]byte{"password": []byte("unrelated")},
	})
	_, err := r.reconcile(context.Background(), api, humanToken(forgev1.AccessTokenAccountHuman, "jake"))
	if err == nil || !strings.Contains(err.Error(), "did not create") {
		t.Fatalf("err=%v", err)
	}
	if len(*requests) != 0 {
		t.Fatalf("requests=%v", *requests)
	}
	var secret corev1.Secret
	if err := r.Get(context.Background(), client.ObjectKey{Namespace: "forgejo", Name: "workstation-token"}, &secret); err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["password"]) != "unrelated" {
		t.Fatal("unrelated Secret was overwritten")
	}
}

// Without a recorded id the operator must not guess: a same-named token on the
// account may be one the person made, so it surfaces Forgejo's refusal instead.
func TestHumanAccessTokenNameCollisionDoesNotRevoke(t *testing.T) {
	r, _, _ := humanHarness(t, humanProvider("jake"), humanAdminSecret())
	var requests []string
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req.Method)
		return response(http.StatusBadRequest, `{"message":"bad `+humanAdminPassword+`"}`), nil
	})
	api, _ := forgeapi.New("https://forgejo.invalid", "admin-api-token", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	_, err := r.reconcile(context.Background(), api, humanToken(forgev1.AccessTokenAccountHuman, "jake"))
	if err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("err=%v", err)
	}
	if strings.Contains(err.Error(), humanAdminPassword) {
		t.Fatal("administrator password leaked into the error")
	}
	if strings.Join(requests, ",") != http.MethodPost {
		t.Fatalf("requests=%v", requests)
	}
}

func TestHumanAccessTokenMissingAdminSecretErrorsBeforeRequest(t *testing.T) {
	r, api, requests := humanHarness(t, humanProvider("jake"))
	_, err := r.reconcile(context.Background(), api, humanToken(forgev1.AccessTokenAccountHuman, "jake"))
	if err == nil || !strings.Contains(err.Error(), "administrator credential") {
		t.Fatalf("err=%v", err)
	}
	if len(*requests) != 0 {
		t.Fatalf("requests=%v", *requests)
	}
}

// failingSecretWrites makes storing the minted token fail.
type failingSecretWrites struct{ client.Client }

func (f failingSecretWrites) Create(ctx context.Context, object client.Object, opts ...client.CreateOption) error {
	if _, ok := object.(*corev1.Secret); ok {
		return errors.New("secret write refused")
	}
	return f.Client.Create(ctx, object, opts...)
}

func TestHumanAccessTokenRevokedWhenItCannotBeStored(t *testing.T) {
	r, api, requests := humanHarness(t, humanProvider("jake"), humanAdminSecret())
	r.Client = failingSecretWrites{r.Client}
	id, err := r.reconcile(context.Background(), api, humanToken(forgev1.AccessTokenAccountHuman, "jake"))
	if err == nil || id != "" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if len(*requests) != 2 || (*requests)[1].method != http.MethodDelete || (*requests)[1].path != "/api/v1/users/jake/tokens/42" || !(*requests)[1].adminAuth {
		t.Fatalf("requests=%v", *requests)
	}
	if strings.Contains(err.Error(), humanMintedToken) {
		t.Fatal("token value leaked into the error")
	}
}

func TestHumanAccessTokenDeleteOnlyAddressesRecordedID(t *testing.T) {
	object := humanToken(forgev1.AccessTokenAccountHuman, "jake")
	r, api, requests := humanHarness(t, humanProvider("jake"), humanAdminSecret())
	if err := r.deleteRemote(context.Background(), api, object, "jake/jake-workstation"); err != nil {
		t.Fatal(err)
	}
	if len(*requests) != 0 {
		t.Fatalf("requests=%v", *requests)
	}
}

const (
	robotTestPassword = "sensitive-robot-password"
	robotMintedToken  = "generated-robot-token"
)

func robotObjects(extra ...client.Object) []client.Object {
	return append([]client.Object{
		&forgev1.ForgejoRobotAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "ci", Namespace: "argo"},
			Spec:       forgev1.RobotAccountSpec{CommonSpec: forgev1.CommonSpec{ProviderRef: "default"}, Username: "ci", PasswordSecretName: "ci-password"},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "ci-password", Namespace: "argo"},
			Data:       map[string][]byte{"password": []byte(robotTestPassword)},
		},
	}, extra...)
}

func robotToken(remoteID string) *forgev1.ForgejoAccessToken {
	object := &forgev1.ForgejoAccessToken{
		TypeMeta:   metav1.TypeMeta{Kind: "ForgejoAccessToken"},
		ObjectMeta: metav1.ObjectMeta{Name: "reader", Namespace: "argo"},
		Spec: forgev1.AccessTokenSpec{
			CommonSpec: forgev1.CommonSpec{ProviderRef: "default"},
			Username:   "ci", Name: "5", SecretName: "reader-token",
		},
	}
	object.Status.RemoteID = remoteID
	return object
}

func robotSecret(nonce string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "reader-token", Namespace: "argo", Annotations: map[string]string{credentials.RotationNonceAnnotation: nonce}},
		Data:       map[string][]byte{"token": []byte("old")},
	}
}

// robotHarness serves a token listing in which id 5 is another token and the CR's
// token, named "5", has id 7. Requests are recorded as "METHOD path" and every one
// is checked to authenticate as the robot, except looking up the account.
func robotHarness(t *testing.T, status func(*http.Request) int, objects ...client.Object) (*managedReconciler, *forgeapi.Client, *[]string) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = forgev1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
	var requests []string
	transport := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.URL.Path != "/api/v1/users/ci" {
			if user, password, _ := r.BasicAuth(); user != "ci" || password != robotTestPassword {
				t.Errorf("%s %s did not authenticate as the robot", r.Method, r.URL.Path)
			}
		}
		if status != nil {
			if code := status(r); code != 0 {
				return response(code, `{"message":"`+robotTestPassword+`"}`), nil
			}
		}
		switch r.Method {
		case http.MethodDelete:
			return response(http.StatusNoContent, ""), nil
		case http.MethodPost:
			return response(http.StatusCreated, `{"id":8,"sha1":"`+robotMintedToken+`"}`), nil
		}
		if r.URL.Query().Get("page") == "1" {
			return response(http.StatusOK, `[{"id":5,"name":"other"},{"id":7,"name":"5"}]`), nil
		}
		return response(http.StatusOK, `[]`), nil
	})
	api, err := forgeapi.New("https://forgejo.invalid", "admin-api-token", forgeapi.WithHTTPClient(&http.Client{Transport: transport}), forgeapi.WithRetries(0))
	if err != nil {
		t.Fatal(err)
	}
	return &managedReconciler{Reconciler: Reconciler{Client: kube}}, api, &requests
}

func requireRequests(t *testing.T, got *[]string, want ...string) {
	t.Helper()
	if strings.Join(*got, ",") != strings.Join(want, ",") {
		t.Fatalf("requests:\n got %s\nwant %s", strings.Join(*got, ","), strings.Join(want, ","))
	}
}

const (
	robotList   = "GET /api/v1/users/ci/tokens"
	robotMint   = "POST /api/v1/users/ci/tokens"
	robotRevoke = "DELETE /api/v1/users/ci/tokens/7"
)

// Forgejo answers 400 to a name already in use, and every deployed CR records
// username/name, so the old token has to be found by its name and revoked first.
func TestRobotAccessTokenRotationRevokesThenMints(t *testing.T) {
	object := robotToken("ci/5")
	object.Spec.RotationNonce = "2"
	r, api, requests := robotHarness(t, nil, robotObjects(robotSecret("1"))...)
	id, err := r.reconcile(context.Background(), api, object)
	if err != nil {
		t.Fatal(err)
	}
	if id != "8" {
		t.Fatalf("id=%q", id)
	}
	requireRequests(t, requests, robotList, robotRevoke, robotMint)
	var secret corev1.Secret
	if err := r.Get(context.Background(), client.ObjectKey{Namespace: "argo", Name: "reader-token"}, &secret); err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["token"]) != robotMintedToken || secret.Annotations[credentials.RotationNonceAnnotation] != "2" {
		t.Fatalf("secret not rotated: %v", secret.Annotations)
	}
}

func TestRobotAccessTokenRotationRetriesAfterTokenAlreadyGone(t *testing.T) {
	object := robotToken("ci/5")
	object.Spec.Name = "absent"
	object.Spec.RotationNonce = "2"
	r, api, requests := robotHarness(t, nil, robotObjects(robotSecret("1"))...)
	if _, err := r.reconcile(context.Background(), api, object); err != nil {
		t.Fatal(err)
	}
	requireRequests(t, requests, robotList, robotList, robotMint)
}

func TestRobotAccessTokenRotationKeepsSecretWhenRevokeFails(t *testing.T) {
	object := robotToken("ci/5")
	object.Spec.RotationNonce = "2"
	r, api, requests := robotHarness(t, func(req *http.Request) int {
		if req.Method == http.MethodDelete {
			return http.StatusUnauthorized
		}
		return 0
	}, robotObjects(robotSecret("1"))...)
	_, err := r.reconcile(context.Background(), api, object)
	if err == nil || strings.Contains(err.Error(), robotTestPassword) {
		t.Fatalf("err=%v", err)
	}
	requireRequests(t, requests, robotList, robotRevoke)
	var secret corev1.Secret
	if err := r.Get(context.Background(), client.ObjectKey{Namespace: "argo", Name: "reader-token"}, &secret); err != nil {
		t.Fatal(err)
	}
	if string(secret.Data["token"]) != "old" || secret.Annotations[credentials.RotationNonceAnnotation] != "1" {
		t.Fatal("secret changed although the rotation failed")
	}
}

// Without an operator annotation nothing says this CR ever minted the token.
func TestRobotAccessTokenFirstMintRevokesNothing(t *testing.T) {
	for name, objects := range map[string][]client.Object{
		"no secret":          robotObjects(),
		"unannotated secret": robotObjects(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "reader-token", Namespace: "argo"}}),
	} {
		t.Run(name, func(t *testing.T) {
			object := robotToken("")
			object.Spec.RotationNonce = "2"
			r, api, requests := robotHarness(t, nil, objects...)
			if _, err := r.reconcile(context.Background(), api, object); err != nil {
				t.Fatal(err)
			}
			requireRequests(t, requests, robotMint)
		})
	}
}

func TestRobotAccessTokenRevokedWhenItCannotBeStored(t *testing.T) {
	r, api, requests := robotHarness(t, nil, robotObjects()...)
	r.Client = failingSecretWrites{r.Client}
	id, err := r.reconcile(context.Background(), api, robotToken(""))
	if err == nil || id != "" || strings.Contains(err.Error(), robotMintedToken) {
		t.Fatalf("id=%q err=%v", id, err)
	}
	requireRequests(t, requests, robotMint, "DELETE /api/v1/users/ci/tokens/8")
}

func TestRobotAccessTokenDeleteUsesRobotPasswordAndResolvedID(t *testing.T) {
	for _, recorded := range []string{"ci/5", "7"} {
		t.Run(recorded, func(t *testing.T) {
			r, api, requests := robotHarness(t, nil, robotObjects()...)
			if err := r.deleteRemote(context.Background(), api, robotToken(recorded), recorded); err != nil {
				t.Fatal(err)
			}
			requireRequests(t, requests, robotList, robotRevoke)
		})
	}
}

func TestRobotAccessTokenDeleteWithoutRecordedIDDoesNothing(t *testing.T) {
	r, api, requests := robotHarness(t, nil, robotObjects()...)
	if err := r.deleteRemote(context.Background(), api, robotToken(""), ""); err != nil {
		t.Fatal(err)
	}
	requireRequests(t, requests)
}

func TestRobotAccessTokenDeleteOfMissingAccountSucceeds(t *testing.T) {
	notFound := func(*http.Request) int { return http.StatusNotFound }
	r, api, requests := robotHarness(t, notFound)
	if err := r.deleteRemote(context.Background(), api, robotToken("ci/5"), "ci/5"); err != nil {
		t.Fatal(err)
	}
	requireRequests(t, requests, "GET /api/v1/users/ci")
}

func TestRobotAccessTokenDeleteKeepsFinalizerWithoutCredential(t *testing.T) {
	r, api, requests := robotHarness(t, func(*http.Request) int { return http.StatusOK })
	err := r.deleteRemote(context.Background(), api, robotToken("ci/5"), "ci/5")
	if err == nil || !strings.Contains(err.Error(), "deletionPolicy Orphan") {
		t.Fatalf("err=%v", err)
	}
	requireRequests(t, requests, "GET /api/v1/users/ci")
}

func TestAccessTokenFailedDeleteIsReportedAndRetried(t *testing.T) {
	now := metav1.Now()
	object := robotToken("ci/5")
	object.Namespace = "argo"
	object.Finalizers = []string{finalizer}
	object.DeletionTimestamp = &now
	object.Spec.DeletionPolicy = forgev1.DeletionPolicyDelete
	object.Status.GeneratedSecrets = []corev1.LocalObjectReference{{Name: "reader-token"}}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = forgev1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&forgev1.ForgejoAccessToken{}).
		WithObjects(append(robotObjects(robotSecret("")), object,
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "admin-token", Namespace: "argo"}, Data: map[string][]byte{"token": []byte("admin")}},
			&forgev1.ForgejoProvider{
				ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "argo"},
				Spec: forgev1.ForgejoProviderSpec{
					URL:            "https://forgejo.invalid",
					TokenSecretRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "admin-token"}, Key: "token"},
				},
			})...).Build()
	transport := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusUnauthorized, `{"message":"denied"}`), nil
	})
	r := &managedReconciler{
		Reconciler: Reconciler{Client: kube, Transport: transport},
		newObject:  func() client.Object { return &forgev1.ForgejoAccessToken{} },
	}
	key := client.ObjectKey{Namespace: "argo", Name: "reader"}
	result, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key})
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter == 0 {
		t.Fatal("a failed delete must be retried")
	}
	var stored forgev1.ForgejoAccessToken
	if err := kube.Get(context.Background(), key, &stored); err != nil {
		t.Fatal(err)
	}
	if !contains(stored.Finalizers, finalizer) {
		t.Fatal("finalizer removed although the token was not revoked")
	}
	if degraded := meta.FindStatusCondition(stored.Status.Conditions, "Degraded"); degraded == nil || degraded.Status != metav1.ConditionTrue {
		t.Fatalf("degraded=%+v", degraded)
	}
	var secret corev1.Secret
	if err := kube.Get(context.Background(), client.ObjectKey{Namespace: "argo", Name: "reader-token"}, &secret); err != nil {
		t.Fatalf("Secret was deleted although the token was not revoked: %v", err)
	}
}
