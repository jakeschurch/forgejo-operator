package controller

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

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

// A real ed25519 public key and the fingerprint `ssh-keygen -lf` prints for it.
const (
	signingKey            = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGXkQmmWeoRqR2jdPRH7PJN8QSpdofdf6hVxXtyMo1Vs git signing key"
	signingKeyFingerprint = "SHA256:1hw8xraY9hwfkBQdq40OJp/YEiwXhC/xAR+Bg679d5c"
)

type fakeSSHForgejo struct {
	admin    bool
	keys     []remoteSSHKey
	conflict bool
	nextID   int64
	requests []string
	sudo     []string
}

func (f *fakeSSHForgejo) roundTrip(r *http.Request) (*http.Response, error) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/")
	f.requests = append(f.requests, r.Method+" "+path)
	f.sudo = append(f.sudo, r.Header.Get("Sudo"))
	encode := func(status int, v any) (*http.Response, error) {
		body, _ := json.Marshal(v)
		return response(status, string(body)), nil
	}
	switch {
	case r.Method == http.MethodGet && strings.HasPrefix(path, "users/jake/keys"):
		want := r.URL.Query().Get("fingerprint")
		var out []remoteSSHKey
		for _, k := range f.keys {
			if want == "" || k.Fingerprint == want {
				out = append(out, k)
			}
		}
		return encode(http.StatusOK, out)
	case r.Method == http.MethodGet && strings.HasPrefix(path, "users/"):
		return encode(http.StatusOK, map[string]any{"login": strings.TrimPrefix(path, "users/"), "is_admin": f.admin})
	// No GET user/keys route: its fingerprint filter ignores the owner, so
	// the controller must never use it (a call fails with 418 here).
	case r.Method == http.MethodPost && path == "user/keys":
		if f.conflict {
			return response(http.StatusUnprocessableEntity, `{"message":"Key content has been used as non-deploy key"}`), nil
		}
		body, _ := io.ReadAll(r.Body)
		var in struct{ Key string }
		_ = json.Unmarshal(body, &in)
		f.nextID++
		created := remoteSSHKey{ID: f.nextID, Fingerprint: "SHA256:" + sshFingerprint(in.Key), Verified: ptr(false)}
		f.keys = append(f.keys, created)
		return encode(http.StatusCreated, created)
	case strings.HasPrefix(path, "user/keys/"):
		for i, k := range f.keys {
			if path == "user/keys/"+jsonInt(k.ID) {
				if r.Method == http.MethodDelete {
					f.keys = append(f.keys[:i], f.keys[i+1:]...)
					return response(http.StatusNoContent, ""), nil
				}
				return encode(http.StatusOK, k)
			}
		}
		return response(http.StatusNotFound, ""), nil
	}
	return response(http.StatusTeapot, ""), nil
}

func jsonInt(v int64) string { b, _ := json.Marshal(v); return string(b) }

func (f *fakeSSHForgejo) count(prefix string) int {
	n := 0
	for _, r := range f.requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func sshKeyFixture(t *testing.T, policy *forgev1.SSHKeyPolicy, mutate func(*forgev1.ForgejoSSHKey)) (*SSHKeyReconciler, client.Client, ctrl.Request, *fakeSSHForgejo) {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = forgev1.AddToScheme(scheme)
	key := &forgev1.ForgejoSSHKey{
		ObjectMeta: metav1.ObjectMeta{Name: "jake-signing", Namespace: "forgejo", Generation: 1},
		Spec: forgev1.SSHKeySpec{
			ProviderRef: "code-jakeschurch", User: "jake", Title: "git signing key",
			PublicKey: signingKey, DeletionPolicy: forgev1.DeletionPolicyOrphan,
		},
	}
	if mutate != nil {
		mutate(key)
	}
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&forgev1.ForgejoSSHKey{}).
		WithObjects(
			key,
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "forgejo-operator-admin", Namespace: "forgejo"},
				Data:       map[string][]byte{"token": []byte("admin-token")},
			},
			&forgev1.ForgejoProvider{
				ObjectMeta: metav1.ObjectMeta{Name: "code-jakeschurch", Namespace: "forgejo"},
				Spec: forgev1.ForgejoProviderSpec{
					URL:            "http://forgejo.invalid:3000",
					ExternalURL:    "https://git.example.invalid",
					TokenSecretRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "forgejo-operator-admin"}, Key: "token"},
					SSHKeys:        policy,
				},
			},
		).Build()
	forgejo := &fakeSSHForgejo{nextID: 40}
	reconciler := &SSHKeyReconciler{Reconciler: Reconciler{Client: kube, Transport: roundTripFunc(forgejo.roundTrip)}}
	return reconciler, kube, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: key.Namespace, Name: key.Name}}, forgejo
}

func storedSSHKey(t *testing.T, kube client.Client, req ctrl.Request) *forgev1.ForgejoSSHKey {
	t.Helper()
	var key forgev1.ForgejoSSHKey
	if err := kube.Get(context.Background(), req.NamespacedName, &key); err != nil {
		t.Fatal(err)
	}
	return &key
}

func sshCondition(t *testing.T, key *forgev1.ForgejoSSHKey, kind string) *metav1.Condition {
	t.Helper()
	c := apimeta.FindStatusCondition(key.Status.Conditions, kind)
	if c == nil {
		t.Fatalf("no %s condition: %#v", kind, key.Status.Conditions)
	}
	return c
}

var allowJake = &forgev1.SSHKeyPolicy{AllowedUsers: []string{"jake"}}

func TestUserKeyFingerprintMatchesOpenSSH(t *testing.T) {
	got, err := userKeyFingerprint(signingKey)
	if err != nil || got != signingKeyFingerprint {
		t.Fatalf("fingerprint = %q, %v; want %q", got, err, signingKeyFingerprint)
	}
	for _, bad := range []string{"", "ssh-ed25519", "ssh-ed25519 !!!", "ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIGXkQmmWeoRqR2jdPRH7PJN8QSpdofdf6hVxXtyMo1Vs"} {
		if _, err := userKeyFingerprint(bad); err == nil {
			t.Errorf("userKeyFingerprint(%q) accepted an invalid key", bad)
		}
	}
}

func TestSSHKeyRegistersUnverifiedKeyAndPointsAtProof(t *testing.T) {
	r, kube, req, forgejo := sshKeyFixture(t, allowJake, nil)
	result, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != sshUnverifiedRequeue {
		t.Fatalf("requeue = %v, want %v while unverified", result.RequeueAfter, sshUnverifiedRequeue)
	}
	if forgejo.count("POST user/keys") != 1 {
		t.Fatalf("requests = %v", forgejo.requests)
	}
	for i, req := range forgejo.requests {
		if !strings.HasPrefix(req, "POST") && !strings.HasPrefix(req, "DELETE") {
			continue
		}
		if forgejo.sudo[i] != "jake" {
			t.Fatalf("%s sent Sudo %q, want jake", req, forgejo.sudo[i])
		}
	}
	key := storedSSHKey(t, kube, req)
	if key.Status.RemoteID != "41" || key.Status.Fingerprint != signingKeyFingerprint || key.Status.Verified == nil || *key.Status.Verified {
		t.Fatalf("status = %#v", key.Status)
	}
	wantURL := "https://git.example.invalid/user/settings/keys?verify_ssh=SHA256%3A1hw8xraY9hwfkBQdq40OJp%2FYEiwXhC%2FxAR%2BBg679d5c"
	if key.Status.VerificationURL != wantURL {
		t.Fatalf("verificationURL = %q, want %q", key.Status.VerificationURL, wantURL)
	}
	if c := sshCondition(t, key, "Ready"); c.Status != metav1.ConditionTrue {
		t.Fatalf("Ready = %#v", c)
	}
	if c := sshCondition(t, key, "Verified"); c.Status != metav1.ConditionFalse || c.Reason != "OwnershipProofRequired" || !strings.Contains(c.Message, wantURL) {
		t.Fatalf("Verified = %#v", c)
	}
	if contains(key.Finalizers, finalizer) {
		t.Fatal("Orphan policy must not add a finalizer")
	}
}

// The owner's proof lives on the remote key row: adopting must never recreate
// it, whatever its title, and status follows Forgejo's verified flag.
func TestSSHKeyAdoptsExistingKeyByFingerprintAndReportsVerified(t *testing.T) {
	r, kube, req, forgejo := sshKeyFixture(t, allowJake, nil)
	forgejo.keys = []remoteSSHKey{{ID: 7, Fingerprint: signingKeyFingerprint, Verified: ptr(true)}}
	result, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if forgejo.count("POST") != 0 || forgejo.count("DELETE") != 0 {
		t.Fatalf("existing key must be adopted untouched: %v", forgejo.requests)
	}
	if result.RequeueAfter != 10*time.Minute {
		t.Fatalf("requeue = %v", result.RequeueAfter)
	}
	key := storedSSHKey(t, kube, req)
	if key.Status.RemoteID != "7" || key.Status.Verified == nil || !*key.Status.Verified {
		t.Fatalf("status = %#v", key.Status)
	}
	if c := sshCondition(t, key, "Verified"); c.Status != metav1.ConditionTrue || c.Reason != "OwnershipProven" {
		t.Fatalf("Verified = %#v", c)
	}
}

func TestSSHKeyRefusesWithoutPolicyOrForAdmins(t *testing.T) {
	cases := map[string]struct {
		policy *forgev1.SSHKeyPolicy
		admin  bool
		ns     string
	}{
		"no policy":         {policy: nil},
		"user not listed":   {policy: &forgev1.SSHKeyPolicy{AllowedUsers: []string{"renovate"}}},
		"site admin target": {policy: allowJake, admin: true},
		"foreign namespace": {policy: allowJake, ns: "argo"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r, kube, req, forgejo := sshKeyFixture(t, tc.policy, func(k *forgev1.ForgejoSSHKey) {
				if tc.ns != "" {
					k.Namespace = tc.ns
					k.Spec.ProviderNamespace = "forgejo"
				}
			})
			forgejo.admin = tc.admin
			if _, err := r.Reconcile(context.Background(), req); err != nil {
				t.Fatal(err)
			}
			if forgejo.count("POST") != 0 || forgejo.count("GET users/jake/keys") != 0 {
				t.Fatalf("unauthorized reconcile touched keys: %v", forgejo.requests)
			}
			key := storedSSHKey(t, kube, req)
			if c := sshCondition(t, key, "Ready"); c.Status != metav1.ConditionFalse || c.Reason != "Unauthorized" {
				t.Fatalf("Ready = %#v", c)
			}
		})
	}
}

func TestSSHKeyReportsFingerprintInUse(t *testing.T) {
	r, kube, req, forgejo := sshKeyFixture(t, allowJake, nil)
	forgejo.conflict = true
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	key := storedSSHKey(t, kube, req)
	if c := sshCondition(t, key, "Ready"); c.Reason != "KeyInUse" {
		t.Fatalf("Ready = %#v", c)
	}
	if c := sshCondition(t, key, "Verified"); c.Status != metav1.ConditionUnknown {
		t.Fatalf("Verified = %#v", c)
	}
}

func TestSSHKeyRejectsMalformedKeyWithoutCallingForgejo(t *testing.T) {
	r, kube, req, forgejo := sshKeyFixture(t, allowJake, func(k *forgev1.ForgejoSSHKey) { k.Spec.PublicKey = "ssh-ed25519 not-base64!" })
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if len(forgejo.requests) != 0 {
		t.Fatalf("requests = %v", forgejo.requests)
	}
	if c := sshCondition(t, storedSSHKey(t, kube, req), "Ready"); c.Status != metav1.ConditionFalse {
		t.Fatalf("Ready = %#v", c)
	}
}

func TestSSHKeyDeletePolicyRemovesOnlyTheDeclaredKey(t *testing.T) {
	r, kube, req, forgejo := sshKeyFixture(t, allowJake, func(k *forgev1.ForgejoSSHKey) { k.Spec.DeletionPolicy = forgev1.DeletionPolicyDelete })
	forgejo.keys = []remoteSSHKey{{ID: 3, Fingerprint: "SHA256:someone-else"}}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	key := storedSSHKey(t, kube, req)
	if !contains(key.Finalizers, finalizer) {
		t.Fatal("Delete policy must add the finalizer")
	}
	if err := kube.Delete(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if forgejo.count("DELETE user/keys/41") != 1 || forgejo.count("DELETE user/keys/3") != 0 {
		t.Fatalf("requests = %v", forgejo.requests)
	}
	if len(forgejo.keys) != 1 || forgejo.keys[0].ID != 3 {
		t.Fatalf("remaining keys = %#v", forgejo.keys)
	}
	var gone forgev1.ForgejoSSHKey
	if err := kube.Get(context.Background(), req.NamespacedName, &gone); err == nil {
		t.Fatal("finalizer was not released")
	}
}

func ptr[T any](v T) *T { return &v }

// Forgejo before 17 omits "verified": report Unknown, not a proof request.
func TestSSHKeyReportsUnknownWhenForgejoOmitsVerified(t *testing.T) {
	r, kube, req, forgejo := sshKeyFixture(t, allowJake, nil)
	forgejo.keys = []remoteSSHKey{{ID: 7, Fingerprint: signingKeyFingerprint}}
	result, err := r.Reconcile(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if result.RequeueAfter != 10*time.Minute {
		t.Fatalf("requeue = %v", result.RequeueAfter)
	}
	key := storedSSHKey(t, kube, req)
	if key.Status.Verified != nil {
		t.Fatalf("verified = %v", *key.Status.Verified)
	}
	if c := sshCondition(t, key, "Verified"); c.Status != metav1.ConditionUnknown || c.Reason != "VerificationNotReported" {
		t.Fatalf("Verified = %#v", c)
	}
}
