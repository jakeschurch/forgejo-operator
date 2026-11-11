package controller

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FORGEJO_BIN points at a disposable local Forgejo; never calls a live service.
func TestIntegrationForgejoGPGKey(t *testing.T) {
	f := startForgejo(t)
	f.createUser(t, "renovate")
	h := newOperatorHarness(t, f)
	api := f.client(t, f.providerToken)
	ctx := context.Background()
	now := time.Now().UTC()
	r := &GPGKeyReconciler{Reconciler: Reconciler{Client: h.kube, Transport: statusLog{t}}, Now: func() time.Time { return now }}
	key := &forgev1.ForgejoGPGKey{ObjectMeta: metav1.ObjectMeta{Name: "renovate", Namespace: integrationNamespace, UID: "integration-gpg"}, Spec: forgev1.GPGKeySpec{
		ProviderRef: "default", User: "renovate", Identity: forgev1.GPGIdentity{Name: "Renovate", Email: "renovate@example.invalid"}, SecretRef: forgev1.GPGSecretRef{Name: "signing-key"},
		Rotation: &forgev1.GPGKeyRotation{After: &metav1.Duration{Duration: time.Hour}, GracePeriod: &metav1.Duration{Duration: 30 * time.Minute}},
	}}
	if err := h.kube.Create(ctx, key); err != nil {
		t.Fatal(err)
	}
	reconcile := func() {
		t.Helper()
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(key)}); err != nil {
			t.Fatal(err)
		}
		if err := h.kube.Get(ctx, client.ObjectKeyFromObject(key), key); err != nil {
			t.Fatal(err)
		}
		if !meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") {
			t.Fatalf("key not ready: %+v", key.Status.Conditions)
		}
	}
	reconcile()
	var secret corev1.Secret
	if err := h.kube.Get(ctx, client.ObjectKey{Namespace: integrationNamespace, Name: "signing-key"}, &secret); err != nil {
		t.Fatal(err)
	}
	private := append([]byte(nil), secret.Data["privateKey"]...)
	first := key.Status.KeyID
	keys, err := listGPG(ctx, api, "renovate")
	if err != nil || len(keys) != 1 || keys[0].KeyID != first {
		t.Fatalf("registration failed: count=%d err=%v", len(keys), err)
	}
	reconcile()
	if err := h.kube.Get(ctx, client.ObjectKeyFromObject(&secret), &secret); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(private, secret.Data["privateKey"]) {
		t.Fatal("idempotent reconcile changed private key")
	}
	// Forgejo must parse this as a signing key whose email belongs to the bot.
	var registered struct {
		CanSign bool `json:"can_sign"`
		Emails  []struct {
			Email    string `json:"email"`
			Verified bool   `json:"verified"`
		} `json:"emails"`
	}
	if err := api.DoSudo(ctx, http.MethodGet, "user/gpg_keys/"+key.Status.RemoteID, "renovate", nil, &registered); err != nil {
		t.Fatal(err)
	}
	if !registered.CanSign || len(registered.Emails) != 1 || !registered.Emails[0].Verified || registered.Emails[0].Email != key.Spec.Identity.Email {
		t.Fatal("Forgejo did not recognize signing capability and activated account email")
	}
	// The real API must accept remote removal and restore the same key.
	if err := api.DoSudo(ctx, http.MethodDelete, "user/gpg_keys/"+key.Status.RemoteID, "renovate", nil, nil); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if key.Status.KeyID != first {
		t.Fatal("re-registration generated a new key")
	}
	now = now.Add(time.Hour)
	reconcile()
	if key.Status.KeyID == first {
		t.Fatal("rotation retained old key")
	}
	keys, err = listGPG(ctx, api, "renovate")
	if err != nil || len(keys) != 2 {
		t.Fatalf("grace lost key: count=%d err=%v", len(keys), err)
	}
	now = now.Add(30 * time.Minute)
	reconcile()
	keys, err = listGPG(ctx, api, "renovate")
	if err != nil || len(keys) != 1 || keys[0].KeyID == first {
		t.Fatalf("retirement failed: count=%d err=%v", len(keys), err)
	}
	if err := h.kube.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(key)}); err != nil {
		t.Fatal(err)
	}
	keys, err = listGPG(ctx, api, "renovate")
	if err != nil || len(keys) != 0 {
		t.Fatalf("deletion failed: count=%d err=%v", len(keys), err)
	}
}
