package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	"github.com/jakeschurch/forgejo-operator/internal/credentials"
	forgeapi "github.com/jakeschurch/forgejo-operator/internal/forgejo"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type gpgFixture struct {
	t                    *testing.T
	r                    *GPGKeyReconciler
	key                  client.ObjectKey
	now                  time.Time
	verified             bool
	admin                bool
	keys                 []remoteGPGKey
	posts, deletes       int
	failPost, failDelete bool
}

func newGPGFixture(t *testing.T) *gpgFixture {
	t.Helper()
	f := &gpgFixture{t: t, key: client.ObjectKey{Namespace: "bots", Name: "signing"}, now: time.Date(2026, 11, 11, 0, 0, 0, 0, time.UTC), verified: true}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = forgev1.AddToScheme(scheme)
	key := &forgev1.ForgejoGPGKey{ObjectMeta: metav1.ObjectMeta{Name: f.key.Name, Namespace: f.key.Namespace, UID: "gpg-owner"}, Spec: forgev1.GPGKeySpec{
		ProviderRef: "shared", ProviderNamespace: "providers", User: "renovate", Identity: forgev1.GPGIdentity{Name: "Renovate", Email: "bot@example.test"}, SecretRef: forgev1.GPGSecretRef{Name: "signing-key"}, DeletionPolicy: forgev1.DeletionPolicyDelete,
	}}
	kube := fake.NewClientBuilder().WithScheme(scheme).WithStatusSubresource(key).WithIndex(&forgev1.ForgejoGPGKey{}, gpgSecretIndex, gpgSecretRefs).WithIndex(&forgev1.ForgejoGPGKey{}, gpgProviderIndex, gpgProviderRefs).WithIndex(&forgev1.ForgejoProvider{}, gpgTokenIndex, gpgTokenRefs).WithObjects(key,
		&forgev1.ForgejoProvider{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "providers"}, Spec: forgev1.ForgejoProviderSpec{GPGKeys: &forgev1.GPGKeyPolicy{AllowedUsers: []string{"renovate"}, AllowedNamespaces: []string{"bots"}}, URL: "https://forgejo.invalid", TokenSecretRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "admin"}, Key: "token"}}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "admin", Namespace: "providers"}, Data: map[string][]byte{"token": []byte("admin-sensitive")}},
	).Build()
	f.r = &GPGKeyReconciler{StateNamespace: "operator-system", Reconciler: Reconciler{Client: kube, Transport: roundTripFunc(f.serve)}, Now: func() time.Time { return f.now }}
	return f
}

func (f *gpgFixture) serve(req *http.Request) (*http.Response, error) {
	f.t.Helper()
	if req.URL.Path == "/api/v1/users/renovate" && req.Header.Get("Sudo") == "" && req.Header.Get("Authorization") == "token admin-sensitive" {
		return response(200, fmt.Sprintf(`{"is_admin":%t}`, f.admin)), nil
	}
	if req.Header.Get("Sudo") != "renovate" || req.Header.Get("Authorization") != "token admin-sensitive" {
		f.t.Fatal("missing sudo/admin authentication")
	}
	if req.URL.Path == "/api/v1/user/emails" {
		return response(200, fmt.Sprintf(`[{"email":"bot@example.test","verified":%t}]`, f.verified)), nil
	}
	if req.URL.Path == "/api/v1/user/gpg_keys" {
		if req.Method == http.MethodGet {
			// Exercise capped pagination: Forgejo returns just one key per page.
			page, _ := strconv.Atoi(req.URL.Query().Get("page"))
			var keys []remoteGPGKey
			if page > 0 && page <= len(f.keys) {
				keys = f.keys[page-1 : page]
			}
			data, _ := json.Marshal(keys)
			return response(200, string(data)), nil
		}
		if req.Method == http.MethodPost {
			var payload map[string]string
			_ = json.NewDecoder(req.Body).Decode(&payload)
			if strings.Contains(payload["armored_public_key"], "PRIVATE") {
				f.t.Fatal("private key sent to Forgejo")
			}
			entities, err := openpgp.ReadArmoredKeyRing(strings.NewReader(payload["armored_public_key"]))
			if err != nil || len(entities) != 1 {
				f.t.Fatal("invalid public key registration")
			}
			if f.failPost {
				return response(422, `{"message":"PRIVATE KEY ECHO MUST NOT LEAK"}`), nil
			}
			f.posts++
			remote := remoteGPGKey{ID: int64(f.posts), KeyID: entities[0].PrimaryKey.KeyIdString()}
			f.keys = append(f.keys, remote)
			data, _ := json.Marshal(remote)
			return response(201, string(data)), nil
		}
	}
	if req.Method == http.MethodDelete && strings.HasPrefix(req.URL.Path, "/api/v1/user/gpg_keys/") {
		if f.failDelete {
			return response(403, `{"message":"PRIVATE KEY ECHO MUST NOT LEAK"}`), nil
		}
		id, _ := strconv.ParseInt(strings.TrimPrefix(req.URL.Path, "/api/v1/user/gpg_keys/"), 10, 64)
		f.keys = slices.DeleteFunc(f.keys, func(key remoteGPGKey) bool { return key.ID == id })
		f.deletes++
		return response(204, ""), nil
	}
	f.t.Fatalf("unexpected request: %s %s", req.Method, req.URL.Path)
	return nil, nil
}

func (f *gpgFixture) reconcile() *forgev1.ForgejoGPGKey {
	f.t.Helper()
	if _, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: f.key}); err != nil {
		f.t.Fatal(err)
	}
	var key forgev1.ForgejoGPGKey
	if err := f.r.Get(context.Background(), f.key, &key); err != nil {
		f.t.Fatal(err)
	}
	return &key
}

func (f *gpgFixture) secret() *corev1.Secret {
	f.t.Helper()
	var secret corev1.Secret
	if err := f.r.Get(context.Background(), client.ObjectKey{Namespace: f.key.Namespace, Name: "signing-key"}, &secret); err != nil {
		f.t.Fatal(err)
	}
	return &secret
}

func (f *gpgFixture) rotation() {
	f.t.Helper()
	key := f.reconcile()
	key.Spec.Rotation = &forgev1.GPGKeyRotation{After: &metav1.Duration{Duration: time.Hour}, GracePeriod: &metav1.Duration{Duration: 30 * time.Minute}}
	if err := f.r.Update(context.Background(), key); err != nil {
		f.t.Fatal(err)
	}
}

func TestGPGKeyLifecycle(t *testing.T) {
	f := newGPGFixture(t)
	key := f.reconcile()
	if !meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || !meta.IsStatusConditionTrue(key.Status.Conditions, "EmailVerified") || !meta.IsStatusConditionTrue(key.Status.Conditions, "KeyRegistered") {
		t.Fatalf("key not ready: %+v", key.Status.Conditions)
	}
	secret := f.secret()
	if len(secret.OwnerReferences) != 1 || secret.OwnerReferences[0].UID != key.UID || key.Status.KeyID == "" || key.Status.Fingerprint == "" {
		t.Fatal("missing ownership or key status")
	}
	for _, name := range []string{"privateKey", "publicKey", "keyID", "fingerprint"} {
		if len(secret.Data[name]) == 0 {
			t.Fatalf("missing output %s", name)
		}
	}
	before := secret.ResourceVersion
	f.reconcile()
	if f.posts != 1 || f.secret().ResourceVersion != before {
		t.Fatal("second reconcile mutated key material")
	}
	f.keys = nil
	f.reconcile()
	if f.posts != 2 || !bytes.Equal(secret.Data["privateKey"], f.secret().Data["privateKey"]) {
		t.Fatal("remote drift must re-register the same key")
	}
	// A missing Secret creates a replacement while retaining old remote cleanup.
	if err := f.r.Delete(context.Background(), f.secret()); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	if f.posts != 3 || len(f.keys) != 2 {
		t.Fatal("Secret-loss recovery lost the previous key")
	}
	key = f.reconcile()
	if err := f.r.Delete(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: f.key}); err != nil {
		t.Fatal(err)
	}
	if len(f.keys) != 0 || f.deletes != 2 {
		t.Fatal("finalizer did not remove all managed keys")
	}
	if err := f.r.Get(context.Background(), f.key, &forgev1.ForgejoGPGKey{}); !apierrors.IsNotFound(err) {
		t.Fatalf("finalizer not released: %v", err)
	}
}

func TestGPGEmailAndSanitizedFailures(t *testing.T) {
	f := newGPGFixture(t)
	f.verified = false
	key := f.reconcile()
	if meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || meta.FindStatusCondition(key.Status.Conditions, "EmailVerified").Reason != "EmailNotActivated" || f.posts != 0 {
		t.Fatal("unverified email accepted")
	}
	var secret corev1.Secret
	if err := f.r.Get(context.Background(), client.ObjectKey{Namespace: f.key.Namespace, Name: "signing-key"}, &secret); !apierrors.IsNotFound(err) {
		t.Fatal("generated credentials before checking email")
	}
	f.verified, f.failPost = true, true
	key = f.reconcile()
	data, _ := json.Marshal(key.Status)
	if bytes.Contains(data, []byte("PRIVATE")) {
		t.Fatal("API error or private material leaked into status")
	}
	if err := f.r.Get(context.Background(), client.ObjectKey{Namespace: f.key.Namespace, Name: "signing-key"}, &secret); !apierrors.IsNotFound(err) {
		t.Fatal("published a Secret before registration succeeded")
	}
	if meta.FindStatusCondition(key.Status.Conditions, "KeyRegistered").Status != metav1.ConditionFalse {
		t.Fatal("registration failure not surfaced")
	}
	f.failPost = false
	f.reconcile()
	secretPtr := f.secret()
	secretPtr.Data["privateKey"] = []byte("PRIVATE KEY ECHO MUST NOT LEAK")
	if err := f.r.Update(context.Background(), secretPtr); err != nil {
		t.Fatal(err)
	}
	key = f.reconcile()
	data, _ = json.Marshal(key.Status)
	if bytes.Contains(data, []byte("PRIVATE KEY ECHO")) || meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") {
		t.Fatal("malformed Secret leaked or was accepted")
	}
}

func TestGPGRotationAndGrace(t *testing.T) {
	f := newGPGFixture(t)
	f.rotation()
	old := string(f.secret().Data["keyID"])
	f.now = f.now.Add(time.Hour)
	key := f.reconcile()
	if key.Status.KeyID == old || f.posts != 2 || len(f.keys) != 2 || len(f.secret().Data[gpgPendingPrivate]) != 0 {
		t.Fatal("rotation did not promote a new key")
	}
	f.now = f.now.Add(29 * time.Minute)
	f.reconcile()
	if f.deletes != 0 {
		t.Fatal("old key removed before grace expired")
	}
	f.now = f.now.Add(time.Minute)
	f.reconcile()
	if f.deletes != 1 || len(f.keys) != 1 {
		t.Fatal("old key not retired after grace")
	}
	key = f.reconcile()
	if len(key.Status.ManagedKeyIDs) != 1 || key.Status.ManagedKeyIDs[0] != key.Status.KeyID {
		t.Fatal("retired journal entry retained")
	}
}

// Reject promotion once to reproduce a crash after successful registration.
type failGPGPromotion struct {
	client.Client
	fail bool
}

func (c *failGPGPromotion) Update(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error {
	if secret, ok := obj.(*corev1.Secret); ok && c.fail && len(secret.Data[gpgPendingPrivate]) == 0 {
		var state gpgState
		_ = json.Unmarshal([]byte(secret.Annotations[gpgStateAnnotation]), &state)
		if len(state.Retiring) > 0 {
			c.fail = false
			return errors.New("simulated promotion conflict")
		}
	}
	return c.Client.Update(ctx, obj, opts...)
}

func TestGPGRotationRecoversAfterRegistrationBeforePromotion(t *testing.T) {
	f := newGPGFixture(t)
	f.rotation()
	old := string(f.secret().Data["keyID"])
	f.r.Client = &failGPGPromotion{Client: f.r.Client, fail: true}
	f.now = f.now.Add(time.Hour)
	f.reconcile()
	if len(f.keys) != 2 || string(f.secret().Data["keyID"]) != old || len(f.secret().Data[gpgPendingPrivate]) == 0 {
		t.Fatal("failed promotion changed mounted key or lost staged key")
	}
	// New controller instance: no in-memory rotation state survives.
	f.r = &GPGKeyReconciler{StateNamespace: "operator-system", Reconciler: f.r.Reconciler, Now: func() time.Time { return f.now }}
	f.reconcile()
	if f.posts != 2 || string(f.secret().Data["keyID"]) == old {
		t.Fatal("restarted rotation duplicated registration or failed promotion")
	}
	f.failDelete = true
	key := f.reconcile()
	if err := f.r.Delete(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	key = f.reconcile()
	if !contains(key.Finalizers, finalizer) || meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") {
		t.Fatal("failed deletion dropped finalizer")
	}
	f.failDelete = false
	// Deletion uses the status journal even if the generated Secret has gone.
	if err := f.r.Delete(context.Background(), f.secret()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: f.key}); err != nil {
		t.Fatal(err)
	}
	if len(f.keys) != 0 {
		t.Fatal("journal did not clean up current and retired key")
	}
}

func TestGPGSecretOwnershipAndKeyMapping(t *testing.T) {
	f := newGPGFixture(t)
	var key forgev1.ForgejoGPGKey
	if err := f.r.Get(context.Background(), f.key, &key); err != nil {
		t.Fatal(err)
	}
	key.Spec.SecretRef.Keys = &forgev1.GPGSecretKeys{PrivateKey: "private.asc", PublicKey: "public.asc", KeyID: "id", Fingerprint: "fp"}
	if err := f.r.Update(context.Background(), &key); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	if len(f.secret().Data["private.asc"]) == 0 || len(f.secret().Data["privateKey"]) != 0 {
		t.Fatal("custom key mapping ignored")
	}
	secret := f.secret()
	secret.OwnerReferences = []metav1.OwnerReference{{UID: "someone-else"}}
	if err := f.r.Update(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	result := f.reconcile()
	if meta.IsStatusConditionTrue(result.Status.Conditions, "Ready") || f.posts != 1 {
		t.Fatal("foreign Secret accepted")
	}
}

func TestGPGEventMappings(t *testing.T) {
	f := newGPGFixture(t)
	for _, obj := range []client.Object{
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "signing-key", Namespace: "bots"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "admin", Namespace: "providers"}},
	} {
		requests := f.r.secretRequests(context.Background(), obj)
		if len(requests) != 1 || requests[0].NamespacedName != f.key {
			t.Fatal("referenced Secret does not enqueue owner")
		}
	}
	requests := f.r.providerRequests(context.Background(), &forgev1.ForgejoProvider{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "providers"}})
	if len(requests) != 1 || requests[0].NamespacedName != f.key {
		t.Fatal("shared provider does not enqueue owner")
	}
}

func TestGPGSecretCannotRetireUnmanagedKeys(t *testing.T) {
	f := newGPGFixture(t)
	f.reconcile()
	f.keys = append(f.keys, remoteGPGKey{ID: 999, KeyID: "DEADBEEF01234567"})
	secret := f.secret()
	var state gpgState
	_ = json.Unmarshal([]byte(secret.Annotations[gpgStateAnnotation]), &state)
	state.Retiring = append(state.Retiring, gpgRetiring{KeyID: "DEADBEEF01234567", RemoveAfter: f.now})
	writeGPGState(secret, state)
	if err := f.r.Update(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	key := f.reconcile()
	if meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || f.deletes != 0 {
		t.Fatal("Secret annotation authorized deletion of an unmanaged key")
	}
}

func TestGeneratedGPGCanSign(t *testing.T) {
	key, err := credentials.GenerateGPG("Renovate", "bot@example.test", "ed25519", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	private, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(key.Private))
	if err != nil {
		t.Fatal(err)
	}
	public, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(key.Public))
	if err != nil {
		t.Fatal(err)
	}
	var signature bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&signature, private[0], strings.NewReader("commit content"), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := openpgp.CheckArmoredDetachedSignature(public, strings.NewReader("commit content"), &signature, nil); err != nil {
		t.Fatal(err)
	}
	// Public serialization must contain no secret packets.
	if public[0].PrivateKey != nil {
		t.Fatal("public export contains private material")
	}
}

func TestGPGProviderAuthorization(t *testing.T) {
	for _, test := range []struct {
		name   string
		policy *forgev1.GPGKeyPolicy
		admin  bool
	}{
		{"disabled", nil, false},
		{"empty_users", &forgev1.GPGKeyPolicy{AllowedNamespaces: []string{"bots"}}, false},
		{"other_user", &forgev1.GPGKeyPolicy{AllowedUsers: []string{"other"}, AllowedNamespaces: []string{"bots"}}, false},
		{"cross_namespace", &forgev1.GPGKeyPolicy{AllowedUsers: []string{"renovate"}}, false},
		{"admin", &forgev1.GPGKeyPolicy{AllowedUsers: []string{"renovate"}, AllowedNamespaces: []string{"bots"}}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newGPGFixture(t)
			var provider forgev1.ForgejoProvider
			ctx := context.Background()
			if err := f.r.Get(ctx, client.ObjectKey{Namespace: "providers", Name: "shared"}, &provider); err != nil {
				t.Fatal(err)
			}
			provider.Spec.GPGKeys = test.policy
			if err := f.r.Update(ctx, &provider); err != nil {
				t.Fatal(err)
			}
			f.admin = test.admin
			requests := 0
			f.r.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				if !test.admin || req.URL.Path != "/api/v1/users/renovate" {
					t.Fatal("authorization failure disclosed target emails or keys")
				}
				return f.serve(req)
			})
			key := f.reconcile()
			if meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || f.posts != 0 {
				t.Fatal("unauthorized request accepted")
			}
			if !test.admin && requests != 0 {
				t.Fatal("provider policy rejection contacted Forgejo")
			}
			var secret corev1.Secret
			if err := f.r.Get(ctx, client.ObjectKey{Namespace: "bots", Name: "signing-key"}, &secret); !apierrors.IsNotFound(err) {
				t.Fatal("unauthorized Secret created")
			}
		})
	}
}

func TestGPGSameNamespaceNeedsNoNamespaceOptIn(t *testing.T) {
	f := newGPGFixture(t)
	ctx := context.Background()
	var provider forgev1.ForgejoProvider
	if err := f.r.Get(ctx, client.ObjectKey{Namespace: "providers", Name: "shared"}, &provider); err != nil {
		t.Fatal(err)
	}
	provider.Namespace, provider.ResourceVersion = "bots", ""
	provider.Spec.GPGKeys.AllowedNamespaces = nil
	if err := f.r.Create(ctx, &provider); err != nil {
		t.Fatal(err)
	}
	if err := f.r.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "admin", Namespace: "bots"}, Data: map[string][]byte{"token": []byte("admin-sensitive")}}); err != nil {
		t.Fatal(err)
	}
	var key forgev1.ForgejoGPGKey
	if err := f.r.Get(ctx, f.key, &key); err != nil {
		t.Fatal(err)
	}
	key.Spec.ProviderNamespace = ""
	if err := f.r.Update(ctx, &key); err != nil {
		t.Fatal(err)
	}
	if !meta.IsStatusConditionTrue(f.reconcile().Status.Conditions, "Ready") {
		t.Fatal("same namespace refused")
	}
}

func TestGPGRefusesPlantedSecret(t *testing.T) {
	f := newGPGFixture(t)
	material, err := credentials.GenerateGPG("Renovate", "bot@example.test", "ed25519", f.now)
	if err != nil {
		t.Fatal(err)
	}
	planted := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "signing-key", Namespace: "bots"}, Data: map[string][]byte{"privateKey": material.Private}}
	if err := f.r.Create(context.Background(), planted); err != nil {
		t.Fatal(err)
	}
	key := f.reconcile()
	if meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || f.posts != 0 || len(f.secret().OwnerReferences) != 0 {
		t.Fatal("planted key adopted or registered")
	}
}

func TestGPGOrphanDeletionWithoutProvider(t *testing.T) {
	for _, policy := range []forgev1.DeletionPolicy{"", forgev1.DeletionPolicyOrphan} {
		t.Run(string(policy), func(t *testing.T) {
			f := newGPGFixture(t)
			ctx := context.Background()
			key := f.reconcile()
			key.Spec.DeletionPolicy = policy
			if err := f.r.Update(ctx, key); err != nil {
				t.Fatal(err)
			}
			key = f.reconcile()
			if contains(key.Finalizers, finalizer) {
				t.Fatal("Orphan retained finalizer")
			}
			if err := f.r.Delete(ctx, &forgev1.ForgejoProvider{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "providers"}}); err != nil {
				t.Fatal(err)
			}
			if err := f.r.Delete(ctx, key); err != nil {
				t.Fatal(err)
			}
			if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: f.key}); err != nil {
				t.Fatal(err)
			}
			if len(f.keys) != 1 || f.deletes != 0 {
				t.Fatal("Orphan removed remote keys")
			}
		})
	}
}

func TestGPGRestoresLostStatusDuringGrace(t *testing.T) {
	f := newGPGFixture(t)
	f.rotation()
	f.now = f.now.Add(time.Hour)
	key := f.reconcile()
	current := key.Status.KeyID
	secret := f.secret()
	var state gpgState
	_ = json.Unmarshal([]byte(secret.Annotations[gpgStateAnnotation]), &state)
	// Valid retirement entries can be recovered only with operator provenance.
	writeGPGState(secret, state)
	if err := f.r.Update(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	key.Status = forgev1.GPGKeyStatus{}
	if err := f.r.Status().Update(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	key = f.reconcile()
	if !meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || key.Status.KeyID != current || len(key.Status.ManagedKeyIDs) != 2 || f.posts != 2 {
		t.Fatal("journal not recovered from owned Secret and remote keys")
	}
	f.now = f.now.Add(30 * time.Minute)
	if len(f.reconcile().Status.ManagedKeyIDs) != 1 || f.deletes != 1 {
		t.Fatal("recovered retirement did not finish")
	}
}

func TestGPGListingBounds(t *testing.T) {
	for _, repeat := range []bool{true, false} {
		t.Run(fmt.Sprint(repeat), func(t *testing.T) {
			calls := 0
			api, err := forgeapi.New("https://forgejo.invalid", "test", forgeapi.WithHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				id := calls
				if repeat {
					id = 1
				}
				return response(200, fmt.Sprintf(`[{"id":%d,"key_id":"ABC"}]`, id)), nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := listGPG(context.Background(), api, "renovate"); err == nil {
				t.Fatal("unbounded listing accepted")
			}
			want := maxGPGPages
			if repeat {
				want = 2
			}
			if calls != want {
				t.Fatalf("listing calls %d, want %d", calls, want)
			}
		})
	}
}

func TestGPGSecretLossDoesNotPublishUnregisteredKey(t *testing.T) {
	f := newGPGFixture(t)
	f.reconcile()
	if err := f.r.Delete(context.Background(), f.secret()); err != nil {
		t.Fatal(err)
	}
	f.failPost = true
	f.reconcile()
	var secret corev1.Secret
	if err := f.r.Get(context.Background(), client.ObjectKey{Namespace: "bots", Name: "signing-key"}, &secret); !apierrors.IsNotFound(err) {
		t.Fatal("Secret-loss recovery published unregistered credentials")
	}
}

// 2026-11-11: Kubernetes allows Secret creators to forge controller owner UIDs.
func TestGPGRefusesForgedOwnerAndStatus(t *testing.T) {
	for _, spoofStatus := range []bool{false, true} {
		t.Run(fmt.Sprint(spoofStatus), func(t *testing.T) {
			f := newGPGFixture(t)
			ctx := context.Background()
			var key forgev1.ForgejoGPGKey
			if err := f.r.Get(ctx, f.key, &key); err != nil {
				t.Fatal(err)
			}
			attacker, err := credentials.GenerateGPG(key.Spec.Identity.Name, key.Spec.Identity.Email, "ed25519", f.now)
			if err != nil {
				t.Fatal(err)
			}
			secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "signing-key", Namespace: "bots"}, Data: map[string][]byte{}}
			if err := ctrl.SetControllerReference(&key, secret, f.r.Scheme()); err != nil {
				t.Fatal(err)
			}
			writeGPGOutputs(secret, [4]string{"privateKey", "publicKey", "keyID", "fingerprint"}, attacker)
			writeGPGState(secret, gpgState{CreatedAt: f.now})
			if err := f.r.Create(ctx, secret); err != nil {
				t.Fatal(err)
			}
			if spoofStatus {
				key.Status.KeyID, key.Status.Fingerprint = attacker.KeyID, attacker.Fingerprint
				key.Status.ManagedKeyIDs = []string{attacker.KeyID}
				if err := f.r.Status().Update(ctx, &key); err != nil {
					t.Fatal(err)
				}
			}
			recorder := record.NewFakeRecorder(5)
			f.r.Recorder = recorder
			key = *f.reconcile()
			if meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || f.posts != 0 || f.deletes != 0 {
				t.Fatal("forged owner/status authorized a key")
			}
			if c := meta.FindStatusCondition(key.Status.Conditions, "KeyRegistered"); c == nil || c.Reason != "SecretTampered" {
				t.Fatal("missing tamper condition")
			}
			select {
			case event := <-recorder.Events:
				if !strings.Contains(event, "SecretTampered") || strings.Contains(event, attacker.Fingerprint) || strings.Contains(event, "BEGIN") {
					t.Fatal("unsafe or missing tamper event")
				}
			default:
				t.Fatal("missing tamper event")
			}
		})
	}
}

func TestGPGRefusesPrivateAndPendingKeySwap(t *testing.T) {
	for _, field := range []string{"privateKey", gpgPendingPrivate} {
		t.Run(field, func(t *testing.T) {
			f := newGPGFixture(t)
			original := f.reconcile()
			attacker, err := credentials.GenerateGPG("Renovate", "bot@example.test", "ed25519", f.now)
			if err != nil {
				t.Fatal(err)
			}
			secret := f.secret()
			secret.Data[field] = attacker.Private
			if err := f.r.Update(context.Background(), secret); err != nil {
				t.Fatal(err)
			}
			f.now = f.now.Add(48 * time.Hour)
			key := f.reconcile()
			condition := meta.FindStatusCondition(key.Status.Conditions, "KeyRegistered")
			if meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || condition == nil || condition.Reason != "SecretTampered" || f.posts != 1 || f.deletes != 0 || key.Status.KeyID != original.Status.KeyID || len(f.keys) != 1 {
				t.Fatal("Secret swap registered/retired a key or lost tamper condition")
			}
			if err := f.r.Delete(context.Background(), f.secret()); err != nil {
				t.Fatal(err)
			}
			key = f.reconcile()
			if !meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || key.Status.KeyID == original.Status.KeyID || key.Status.KeyID == attacker.KeyID || f.posts != 2 {
				t.Fatal("Secret deletion did not recover with a fresh minted key")
			}
		})
	}
}

func TestGPGDeauthorizationRevokesAndAllowsDeletion(t *testing.T) {
	for _, admin := range []bool{false, true} {
		for _, deleting := range []bool{false, true} {
			t.Run(fmt.Sprintf("admin=%t/deleting=%t", admin, deleting), func(t *testing.T) {
				f := newGPGFixture(t)
				ctx := context.Background()
				key := f.reconcile()
				// Unrelated keys on the same account must survive revocation.
				f.keys = append(f.keys, remoteGPGKey{ID: 999, KeyID: "DEADBEEF01234567"})
				if admin {
					f.admin = true
				} else {
					var provider forgev1.ForgejoProvider
					if err := f.r.Get(ctx, client.ObjectKey{Namespace: "providers", Name: "shared"}, &provider); err != nil {
						t.Fatal(err)
					}
					provider.Spec.GPGKeys.AllowedUsers = nil
					if err := f.r.Update(ctx, &provider); err != nil {
						t.Fatal(err)
					}
				}
				if deleting {
					if err := f.r.Delete(ctx, key); err != nil {
						t.Fatal(err)
					}
					if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: f.key}); err != nil {
						t.Fatal(err)
					}
				} else {
					key = f.reconcile()
					if meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") {
						t.Fatal("deauthorized key ready")
					}
					if err := f.r.Delete(ctx, key); err != nil {
						t.Fatal(err)
					}
					if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: f.key}); err != nil {
						t.Fatal(err)
					}
				}
				if f.posts != 1 || f.deletes != 1 || len(f.keys) != 1 || f.keys[0].ID != 999 {
					t.Fatal("revocation did not remove only the minted key")
				}
				if err := f.r.Get(ctx, f.key, &forgev1.ForgejoGPGKey{}); !apierrors.IsNotFound(err) {
					t.Fatalf("deauthorization stuck finalizer: %v", err)
				}
			})
		}
	}
}

func TestGPGNeverAuthorizedDeleteNeedsNoProvider(t *testing.T) {
	f := newGPGFixture(t)
	ctx := context.Background()
	if err := f.r.Delete(ctx, &forgev1.ForgejoProvider{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "providers"}}); err != nil {
		t.Fatal(err)
	}
	key := f.reconcile()
	if err := f.r.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: f.key}); err != nil {
		t.Fatal(err)
	}
	if err := f.r.Get(ctx, f.key, &forgev1.ForgejoGPGKey{}); !apierrors.IsNotFound(err) {
		t.Fatalf("empty cleanup journal stuck finalizer: %v", err)
	}
}

func TestGPGRefusesUnknownStatusJournalEvenOnDeletion(t *testing.T) {
	for _, deleting := range []bool{false, true} {
		t.Run(fmt.Sprint(deleting), func(t *testing.T) {
			f := newGPGFixture(t)
			ctx := context.Background()
			key := f.reconcile()
			const stranger = "DEADBEEF01234567"
			f.keys = append(f.keys, remoteGPGKey{ID: 999, KeyID: stranger})
			key.Status.ManagedKeyIDs = append(key.Status.ManagedKeyIDs, stranger)
			if err := f.r.Status().Update(ctx, key); err != nil {
				t.Fatal(err)
			}
			secret := f.secret()
			var state gpgState
			_ = json.Unmarshal([]byte(secret.Annotations[gpgStateAnnotation]), &state)
			state.Retiring = append(state.Retiring, gpgRetiring{KeyID: stranger, RemoveAfter: f.now})
			writeGPGState(secret, state)
			if err := f.r.Update(ctx, secret); err != nil {
				t.Fatal(err)
			}
			if deleting {
				if err := f.r.Delete(ctx, key); err != nil {
					t.Fatal(err)
				}
				if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: f.key}); err != nil {
					t.Fatal(err)
				}
				if f.deletes != 1 || len(f.keys) != 1 || f.keys[0].ID != 999 {
					t.Fatal("deletion trusted an unknown journal ID or failed to revoke the proven key")
				}
			} else {
				key = f.reconcile()
				if meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || f.deletes != 0 || len(f.keys) != 2 {
					t.Fatal("unproven status/annotation entry authorized deletion")
				}
			}
		})
	}
}

func TestGPGStatusLossDoesNotTrustAnnotationJournal(t *testing.T) {
	f := newGPGFixture(t)
	key := f.reconcile()
	f.keys = append(f.keys, remoteGPGKey{ID: 999, KeyID: "DEADBEEF01234567"})
	secret := f.secret()
	writeGPGState(secret, gpgState{CreatedAt: f.now, Retiring: []gpgRetiring{{KeyID: "DEADBEEF01234567", RemoveAfter: f.now}}})
	if err := f.r.Update(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	key.Status = forgev1.GPGKeyStatus{}
	if err := f.r.Status().Update(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	key = f.reconcile()
	if meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || f.deletes != 0 || len(f.keys) != 2 {
		t.Fatal("status loss let annotation authorize deletion")
	}
}

func TestGPGRevocationWithOrphanAndTamperedStatus(t *testing.T) {
	f := newGPGFixture(t)
	ctx := context.Background()
	key := f.reconcile()
	key.Spec.DeletionPolicy = forgev1.DeletionPolicyOrphan
	if err := f.r.Update(ctx, key); err != nil {
		t.Fatal(err)
	}
	key.Status = forgev1.GPGKeyStatus{ManagedKeyIDs: []string{"DEADBEEF01234567"}}
	f.keys = append(f.keys, remoteGPGKey{ID: 999, KeyID: "DEADBEEF01234567"})
	if err := f.r.Status().Update(ctx, key); err != nil {
		t.Fatal(err)
	}
	f.admin = true
	key = f.reconcile()
	if len(f.keys) != 1 || f.keys[0].ID != 999 || f.deletes != 1 || meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") {
		t.Fatal("Orphan/tampered status prevented authorization revocation or removed an unknown key")
	}
}

type failGPGJournal struct{ client.Client }

func (c *failGPGJournal) Create(ctx context.Context, object client.Object, opts ...client.CreateOption) error {
	if _, ok := object.(*corev1.ConfigMap); ok {
		return errors.New("simulated provenance storage failure")
	}
	return c.Client.Create(ctx, object, opts...)
}
func TestGPGProvenanceMustPersistBeforePublication(t *testing.T) {
	f := newGPGFixture(t)
	f.r.Client = &failGPGJournal{Client: f.r.Client}
	key := f.reconcile()
	if f.posts != 0 || meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") {
		t.Fatal("registered key before minting provenance persisted")
	}
	var secret corev1.Secret
	if err := f.r.Get(context.Background(), client.ObjectKey{Namespace: "bots", Name: "signing-key"}, &secret); !apierrors.IsNotFound(err) {
		t.Fatal("published private key without provenance")
	}
}
