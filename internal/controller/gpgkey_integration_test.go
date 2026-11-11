package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	"github.com/jakeschurch/forgejo-operator/internal/credentials"
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
	var provider forgev1.ForgejoProvider
	if err := h.kube.Get(ctx, client.ObjectKey{Namespace: integrationNamespace, Name: "default"}, &provider); err != nil {
		t.Fatal(err)
	}
	provider.Spec.GPGKeys = &forgev1.GPGKeyPolicy{AllowedUsers: []string{"renovate"}}
	if err := h.kube.Update(ctx, &provider); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	r := &GPGKeyReconciler{StateNamespace: "operator-system", Reconciler: Reconciler{Client: h.kube, Transport: statusLog{t}}, Now: func() time.Time { return now }}
	key := &forgev1.ForgejoGPGKey{ObjectMeta: metav1.ObjectMeta{Name: "renovate", Namespace: integrationNamespace, UID: "integration-gpg"}, Spec: forgev1.GPGKeySpec{
		ProviderRef: "default", User: "renovate", Identity: forgev1.GPGIdentity{Name: "Renovate", Email: "renovate@example.invalid"}, SecretRef: forgev1.GPGSecretRef{Name: "signing-key"}, DeletionPolicy: forgev1.DeletionPolicyDelete,
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
	// A Secret writer cannot replace the private key even with legitimate ownership.
	attacker, err := credentials.GenerateGPG(key.Spec.Identity.Name, key.Spec.Identity.Email, "ed25519", now)
	if err != nil {
		t.Fatal(err)
	}
	secret.Data["privateKey"] = attacker.Private
	if err := h.kube.Update(ctx, &secret); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(key)}); err != nil {
		t.Fatal(err)
	}
	if err := h.kube.Get(ctx, client.ObjectKeyFromObject(key), key); err != nil {
		t.Fatal(err)
	}
	condition := meta.FindStatusCondition(key.Status.Conditions, "KeyRegistered")
	if condition == nil || condition.Reason != "SecretTampered" || key.Status.KeyID != first {
		t.Fatal("replacement private key accepted")
	}
	keys, err = listGPG(ctx, api, "renovate")
	if err != nil || len(keys) != 1 || keys[0].KeyID != first {
		t.Fatalf("tampering altered registered key: %v", err)
	}
	secret.Data["privateKey"] = private
	if err := h.kube.Update(ctx, &secret); err != nil {
		t.Fatal(err)
	}
	reconcile()
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
	// Policy revocation and administrator promotion must each revoke the minted
	// key, then still permit Delete cleanup without the creation authorization gate.
	provider.Spec.GPGKeys.AllowedUsers = nil
	if err := h.kube.Update(ctx, &provider); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(key)}); err != nil {
		t.Fatal(err)
	}
	keys, err = listGPG(ctx, api, "renovate")
	if err != nil || len(keys) != 1 {
		t.Fatalf("policy blip revoked without debounce: %v", err)
	}
	// State timestamps round upward to whole seconds; allow that extra second.
	now = now.Add(time.Minute + time.Second)
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(key)}); err != nil {
		t.Fatal(err)
	}
	keys, err = listGPG(ctx, api, "renovate")
	if err != nil || len(keys) != 0 {
		t.Fatalf("allowlist revocation kept signing key: %v", err)
	}
	provider.Spec.GPGKeys.AllowedUsers = []string{"renovate"}
	if err := h.kube.Update(ctx, &provider); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if err := api.Do(ctx, http.MethodPatch, "admin/users/renovate", map[string]any{"admin": true}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(key)}); err != nil {
		t.Fatal(err)
	}
	keys, err = listGPG(ctx, api, "renovate")
	if err != nil || len(keys) != 0 {
		t.Fatalf("administrator promotion kept signing key: %v", err)
	}
	if err := h.kube.Get(ctx, client.ObjectKeyFromObject(key), key); err != nil {
		t.Fatal(err)
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

// Reproduce the reviewer's Forgejo 17 attack: create a CR before namespace
// opt-in, then plant an offline key with its publicly readable owner UID.
func TestIntegrationForgejoGPGForgedOwner(t *testing.T) {
	f := startForgejo(t)
	f.createUser(t, "renovate")
	h := newOperatorHarness(t, f)
	ctx := context.Background()
	api := f.client(t, f.providerToken)
	var provider forgev1.ForgejoProvider
	if err := h.kube.Get(ctx, client.ObjectKey{Namespace: integrationNamespace, Name: "default"}, &provider); err != nil {
		t.Fatal(err)
	}
	provider.Spec.GPGKeys = &forgev1.GPGKeyPolicy{AllowedUsers: []string{"renovate"}}
	if err := h.kube.Update(ctx, &provider); err != nil {
		t.Fatal(err)
	}
	key := &forgev1.ForgejoGPGKey{ObjectMeta: metav1.ObjectMeta{Namespace: "argo", Name: "forged", UID: "forged-cr-uid"}, Spec: forgev1.GPGKeySpec{ProviderRef: "default", ProviderNamespace: integrationNamespace, User: "renovate", Identity: forgev1.GPGIdentity{Name: "Renovate", Email: "renovate@example.invalid"}, SecretRef: forgev1.GPGSecretRef{Name: "forged-key"}}}
	if err := h.kube.Create(ctx, key); err != nil {
		t.Fatal(err)
	}
	r := &GPGKeyReconciler{StateNamespace: "operator-system", Reconciler: Reconciler{Client: h.kube, Transport: statusLog{t}}}
	reconcile := func() {
		t.Helper()
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(key)}); err != nil {
			t.Fatal(err)
		}
		if err := h.kube.Get(ctx, client.ObjectKeyFromObject(key), key); err != nil {
			t.Fatal(err)
		}
	}

	attacker, err := credentials.GenerateGPG(key.Spec.Identity.Name, key.Spec.Identity.Email, "ed25519", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// Pre-create the old reflected journal before the operator ever sees the CR.
	ref, _ := r.journalKey(key)
	forged, _ := json.Marshal(map[string]any{"minted": map[string]string{attacker.KeyID: attacker.Fingerprint}, "currentID": attacker.KeyID})
	if err := h.kube.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: r.StateNamespace, Annotations: map[string]string{"reflector.v1.k8s.emberstack.com/reflects": "argo/forged"}}, Data: map[string]string{"journal": string(forged)}}); err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "argo", Name: "forged-key"}, Data: map[string][]byte{"privateKey": attacker.Private}}
	controller := true
	secret.OwnerReferences = []metav1.OwnerReference{{APIVersion: forgev1.GroupVersion.String(), Kind: "ForgejoGPGKey", Name: key.Name, UID: key.UID, Controller: &controller}}
	if err := h.kube.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	provider.Spec.GPGKeys.AllowedNamespaces = []string{"argo"}
	if err := h.kube.Update(ctx, &provider); err != nil {
		t.Fatal(err)
	}
	reconcile()
	condition := meta.FindStatusCondition(key.Status.Conditions, "KeyRegistered")
	if meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || condition == nil || condition.Reason != "SecretTampered" || key.Status.KeyID != "" {
		t.Fatal("forged owner adopted attacker key")
	}
	keys, err := listGPG(ctx, api, "renovate")
	if err != nil || len(keys) != 0 {
		t.Fatalf("planted key registered: %v", err)
	}
	if err := h.kube.Delete(ctx, secret); err != nil {
		t.Fatal(err)
	}
	reconcile()
	if !meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || key.Status.KeyID == attacker.KeyID {
		t.Fatal("deleting planted Secret did not mint a new key")
	}
}

// Exercise both rotations and hostile lifecycle mirrors against Forgejo itself.
func TestIntegrationForgejoGPGProtectedLifecycle(t *testing.T) {
	f := startForgejo(t)
	f.createUser(t, "renovate")
	h := newOperatorHarness(t, f)
	ctx := context.Background()
	api := f.client(t, f.providerToken)
	var provider forgev1.ForgejoProvider
	if err := h.kube.Get(ctx, client.ObjectKey{Namespace: integrationNamespace, Name: "default"}, &provider); err != nil {
		t.Fatal(err)
	}
	provider.Spec.GPGKeys = &forgev1.GPGKeyPolicy{AllowedUsers: []string{"renovate"}}
	if err := h.kube.Update(ctx, &provider); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	r := &GPGKeyReconciler{StateNamespace: "operator-system", Reconciler: Reconciler{Client: h.kube, Transport: statusLog{t}}, Now: func() time.Time { return now }}
	key := &forgev1.ForgejoGPGKey{ObjectMeta: metav1.ObjectMeta{Name: "protected", Namespace: integrationNamespace, UID: "protected-lifecycle"}, Spec: forgev1.GPGKeySpec{ProviderRef: "default", User: "renovate", Identity: forgev1.GPGIdentity{Name: "Renovate", Email: "renovate@example.invalid"}, SecretRef: forgev1.GPGSecretRef{Name: "protected"}, Rotation: &forgev1.GPGKeyRotation{After: &metav1.Duration{Duration: time.Hour}, GracePeriod: &metav1.Duration{Duration: 30 * time.Minute}}}}
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
			t.Fatalf("not ready: %+v", key.Status.Conditions)
		}
	}
	verify := func() {
		t.Helper()
		var remote struct {
			CanSign bool `json:"can_sign"`
			Emails  []struct {
				Verified bool `json:"verified"`
			} `json:"emails"`
		}
		if err := api.DoSudo(ctx, http.MethodGet, "user/gpg_keys/"+key.Status.RemoteID, "renovate", nil, &remote); err != nil {
			t.Fatal(err)
		}
		if !remote.CanSign || len(remote.Emails) != 1 || !remote.Emails[0].Verified {
			t.Fatal("rotated key not verified/can_sign")
		}
	}
	reconcile()
	verify()
	// Human-uploaded keys may never become retirement targets through mirrors.
	human, err := credentials.GenerateGPG(key.Spec.Identity.Name, key.Spec.Identity.Email, "ed25519", now)
	if err != nil {
		t.Fatal(err)
	}
	var foreign remoteGPGKey
	if err := api.DoSudo(ctx, http.MethodPost, "user/gpg_keys", "renovate", map[string]string{"armored_public_key": string(human.Public)}, &foreign); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		current := key.Status.KeyID
		var secret corev1.Secret
		secretRef := client.ObjectKey{Namespace: key.Namespace, Name: key.Spec.SecretRef.Name}
		if err := h.kube.Get(ctx, secretRef, &secret); err != nil {
			t.Fatal(err)
		}
		writeGPGState(&secret, gpgState{CreatedAt: now.Add(-10000 * time.Hour), Retiring: []gpgRetiring{{KeyID: human.KeyID, RemoveAfter: now}}})
		if err := h.kube.Update(ctx, &secret); err != nil {
			t.Fatal(err)
		}
		key.Status.ManagedKeyIDs = append(key.Status.ManagedKeyIDs, human.KeyID)
		if err := h.kube.Status().Update(ctx, key); err != nil {
			t.Fatal(err)
		}
		reconcile()
		if key.Status.KeyID != current {
			t.Fatal("past annotation forced rotation")
		}
		now = now.Add(time.Hour)
		reconcile()
		verify()
		if key.Status.KeyID == current {
			t.Fatal("rotation did not happen")
		}
		if err := h.kube.Get(ctx, secretRef, &secret); err != nil {
			t.Fatal(err)
		}
		writeGPGState(&secret, gpgState{CreatedAt: now.Add(10000 * time.Hour), Retiring: []gpgRetiring{{KeyID: current, RemoveAfter: now.Add(-time.Hour)}}})
		if err := h.kube.Update(ctx, &secret); err != nil {
			t.Fatal(err)
		}
		reconcile()
		keys, err := listGPG(ctx, api, "renovate")
		if err != nil || len(keys) != 3 {
			t.Fatalf("annotation shortened grace or removed foreign key: count=%d err=%v", len(keys), err)
		}
		now = now.Add(30 * time.Minute)
		reconcile()
		key.Status = forgev1.GPGKeyStatus{}
		if err := h.kube.Status().Update(ctx, key); err != nil {
			t.Fatal(err)
		}
		reconcile()
		verify()
		journal, err := r.readGPGJournal(ctx, key)
		if err != nil || len(journal.Minted) != 1 || len(journal.Retiring) != 0 || len(key.Status.ManagedKeyIDs) != 1 {
			t.Fatal("status wipe rearmed removed/foreign IDs")
		}
		keys, err = listGPG(ctx, api, "renovate")
		if err != nil || len(keys) != 2 {
			t.Fatal("protected retirement failed")
		}
	}
}
