package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	"github.com/jakeschurch/forgejo-operator/internal/credentials"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func (f *gpgFixture) journal() *gpgJournal {
	f.t.Helper()
	var key forgev1.ForgejoGPGKey
	if err := f.r.Get(context.Background(), f.key, &key); err != nil {
		f.t.Fatal(err)
	}
	journal, err := f.r.readGPGJournal(context.Background(), &key)
	if err != nil {
		f.t.Fatal(err)
	}
	return journal
}

func TestGPGStateReservedBeforeAuthorization(t *testing.T) {
	f := newGPGFixture(t)
	f.r.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		var states forgev1.ForgejoGPGKeyStateList
		if err := f.r.List(req.Context(), &states); err != nil || len(states.Items) != 1 || len(states.Items[0].Spec.Minted) != 0 {
			t.Fatal("remote access preceded empty state reservation")
		}
		// Stop after the authorization lookup so this assertion only sees empty state.
		return response(200, `{"is_admin":true}`), nil
	})
	f.reconcile()
}

func TestGPGRefusesForeignAndPredatingState(t *testing.T) {
	for _, mode := range []string{"foreign_uid", "foreign_name", "foreign_namespace", "foreign_operator", "predates", "owner_reference"} {
		t.Run(mode, func(t *testing.T) {
			f := newGPGFixture(t)
			var key forgev1.ForgejoGPGKey
			ctx := context.Background()
			if err := f.r.Get(ctx, f.key, &key); err != nil {
				t.Fatal(err)
			}
			ref, _ := f.r.journalKey(&key)
			state := &forgev1.ForgejoGPGKeyState{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, CreationTimestamp: metav1.NewTime(f.now), Annotations: map[string]string{gpgSourceUID: string(key.UID), gpgSourceName: key.Name, gpgSourceNamespace: key.Namespace, gpgStateOperator: f.r.StateNamespace}}, Spec: forgev1.GPGKeyStateSpec{Minted: map[string]string{"ATTACKER": "FORGED"}, CurrentID: "ATTACKER"}}
			switch mode {
			case "foreign_uid":
				state.Annotations[gpgSourceUID] = "other"
			case "foreign_name":
				state.Annotations[gpgSourceName] = "other"
			case "foreign_namespace":
				state.Annotations[gpgSourceNamespace] = "other"
			case "foreign_operator":
				delete(state.Annotations, gpgStateOperator)
			case "predates":
				state.CreationTimestamp = metav1.NewTime(f.now.Add(-time.Second))
			case "owner_reference":
				state.OwnerReferences = []metav1.OwnerReference{{UID: key.UID}}
			}
			if err := f.r.Create(ctx, state); err != nil {
				t.Fatal(err)
			}
			f.r.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("foreign state reached Forgejo"); return nil, nil })
			got := f.reconcile()
			if meta.IsStatusConditionTrue(got.Status.Conditions, "Ready") || len(got.Finalizers) != 0 {
				t.Fatal("foreign state accepted")
			}
		})
	}
}

func TestGPGForgedConfigMapIgnored(t *testing.T) {
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
	ref, _ := f.r.journalKey(&key)
	forged, _ := json.Marshal(map[string]any{"minted": map[string]string{attacker.KeyID: attacker.Fingerprint}, "currentID": attacker.KeyID})
	if err := f.r.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: f.r.StateNamespace, Annotations: map[string]string{"reflector.v1.k8s.emberstack.com/reflects": "tenant/forged"}}, Data: map[string]string{"journal": string(forged)}}); err != nil {
		t.Fatal(err)
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: key.Spec.SecretRef.Name, Namespace: key.Namespace, OwnerReferences: []metav1.OwnerReference{*metav1.NewControllerRef(&key, forgev1.GroupVersion.WithKind("ForgejoGPGKey"))}}, Data: map[string][]byte{}}
	writeGPGOutputs(secret, [4]string{"privateKey", "publicKey", "keyID", "fingerprint"}, attacker)
	if err := f.r.Create(ctx, secret); err != nil {
		t.Fatal(err)
	}
	got := f.reconcile()
	if meta.IsStatusConditionTrue(got.Status.Conditions, "Ready") || f.posts != 0 || len(f.journal().Minted) != 0 {
		t.Fatal("ConfigMap became provenance")
	}
}

func TestGPGAnnotationCannotChangeRotationOrGrace(t *testing.T) {
	f := newGPGFixture(t)
	f.rotation()
	first := f.reconcile().Status.KeyID
	// A past clock cannot force rotation; malformed mirrors also heal.
	for _, raw := range []string{`{"createdAt":"2000-01-01T00:00:00Z"}`, "invalid JSON"} {
		secret := f.secret()
		secret.Annotations[gpgStateAnnotation] = raw
		if err := f.r.Update(context.Background(), secret); err != nil {
			t.Fatal(err)
		}
		if got := f.reconcile(); !meta.IsStatusConditionTrue(got.Status.Conditions, "Ready") || got.Status.KeyID != first || f.posts != 1 {
			t.Fatal("annotation forced rotation or blocked reconcile")
		}
	}
	f.now = f.now.Add(time.Hour)
	second := f.reconcile().Status.KeyID
	if second == first {
		t.Fatal("protected clock did not rotate")
	}
	secret := f.secret()
	writeGPGState(secret, gpgState{CreatedAt: f.now.Add(1000 * time.Hour), Retiring: []gpgRetiring{{KeyID: first, RemoveAfter: f.now.Add(-time.Hour)}}})
	if err := f.r.Update(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	if f.deletes != 0 {
		t.Fatal("annotation shortened grace")
	}
	f.now = f.now.Add(30 * time.Minute)
	f.reconcile()
	if f.deletes != 1 || len(f.journal().Minted) != 1 {
		t.Fatal("protected grace failed or fingerprint was not pruned")
	}
	f.now = f.now.Add(30 * time.Minute)
	if f.reconcile().Status.KeyID == second {
		t.Fatal("future annotation disabled rotation")
	}
}

func TestGPGStatusWipeNeverRearmsRemovedKeys(t *testing.T) {
	f := newGPGFixture(t)
	f.rotation()
	for i := 0; i < 2; i++ {
		f.now = f.now.Add(time.Hour)
		f.reconcile()
		f.now = f.now.Add(30 * time.Minute)
		f.reconcile()
	}
	key := f.reconcile()
	current := key.Status.KeyID
	key.Status = forgev1.GPGKeyStatus{}
	if err := f.r.Status().Update(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	key = f.reconcile()
	if !meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || len(key.Status.ManagedKeyIDs) != 1 || key.Status.KeyID != current || len(f.journal().Retiring) != 0 || len(f.journal().Minted) != 1 {
		t.Fatal("status wipe rearmed removed keys")
	}
	f.now = f.now.Add(30 * time.Minute)
	if f.reconcile().Status.KeyID == current {
		t.Fatal("status wipe stalled next rotation")
	}
}

func TestGPGUnknownMirrorsWarnAndHeal(t *testing.T) {
	f := newGPGFixture(t)
	recorder := record.NewFakeRecorder(10)
	f.r.Recorder = recorder
	key := f.reconcile()
	key.Status.KeyID = "FOREIGN"
	key.Status.ManagedKeyIDs = append(key.Status.ManagedKeyIDs, "FOREIGN")
	if err := f.r.Status().Update(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	secret := f.secret()
	writeGPGState(secret, gpgState{Retiring: []gpgRetiring{{KeyID: "FOREIGN", RemoveAfter: f.now}}})
	if err := f.r.Update(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	key = f.reconcile()
	if !meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || len(key.Status.ManagedKeyIDs) != 1 || key.Status.KeyID == "FOREIGN" || f.deletes != 0 {
		t.Fatal("unknown mirrors wedged or expanded cleanup")
	}
	select {
	case event := <-recorder.Events:
		if !strings.Contains(event, "UntrustedGPGMirror") {
			t.Fatal(event)
		}
	default:
		t.Fatal("missing warning")
	}
}

func TestGPGDeauthorizationDebounce(t *testing.T) {
	for _, mode := range []string{"user", "namespace", "disabled", "admin", "admin_and_disabled"} {
		t.Run(mode, func(t *testing.T) {
			f := newGPGFixture(t)
			f.reconcile()
			ctx := context.Background()
			var provider forgev1.ForgejoProvider
			ref := client.ObjectKey{Namespace: "providers", Name: "shared"}
			if err := f.r.Get(ctx, ref, &provider); err != nil {
				t.Fatal(err)
			}
			original := provider.Spec.GPGKeys.DeepCopy()
			deny := func() {
				if err := f.r.Get(ctx, ref, &provider); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "user":
					provider.Spec.GPGKeys.AllowedUsers = nil
				case "namespace":
					provider.Spec.GPGKeys.AllowedNamespaces = nil
				case "disabled":
					provider.Spec.GPGKeys = nil
				case "admin":
					f.admin = true
				case "admin_and_disabled":
					f.admin = true
					provider.Spec.GPGKeys = nil
				}
				if err := f.r.Update(ctx, &provider); err != nil {
					t.Fatal(err)
				}
			}
			deny()
			f.reconcile()
			if strings.HasPrefix(mode, "admin") {
				if f.deletes != 1 {
					t.Fatal("admin revocation delayed")
				}
				return
			}
			if f.deletes != 0 {
				t.Fatal("first observation revoked")
			}
			f.now = f.now.Add(59 * time.Second)
			f.reconcile()
			if f.deletes != 0 {
				t.Fatal("revocation before 60s")
			}
			// A policy recovery resets the persisted debounce, even across restarts.
			if err := f.r.Get(ctx, ref, &provider); err != nil {
				t.Fatal(err)
			}
			provider.Spec.GPGKeys = original
			if err := f.r.Update(ctx, &provider); err != nil {
				t.Fatal(err)
			}
			f.reconcile()
			if f.journal().UnauthorizedSince != nil {
				t.Fatal("authorized observation did not reset debounce")
			}
			deny()
			f.reconcile()
			f.r = &GPGKeyReconciler{Reconciler: f.r.Reconciler, StateNamespace: f.r.StateNamespace, Now: func() time.Time { return f.now }}
			f.now = f.now.Add(59 * time.Second)
			f.reconcile()
			if f.deletes != 0 {
				t.Fatal("reset sequence revoked early")
			}
			f.now = f.now.Add(time.Second)
			f.reconcile()
			if f.deletes != 1 {
				t.Fatal("persistent deauthorization did not revoke")
			}
		})
	}
}

func TestGPGRepeatedPublicationFailuresBoundProvenance(t *testing.T) {
	f := newGPGFixture(t)
	f.failPost = true
	for i := 0; i < maxGPGMinted+2; i++ {
		f.reconcile()
	}
	if len(f.journal().Minted) != maxGPGMinted {
		t.Fatal("unbounded fingerprints")
	}
	f.now = f.now.Add(gpgGrace)
	f.failPost = false
	key := f.reconcile()
	if !meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || len(f.journal().Minted) != 1 {
		t.Fatal("capped provenance failed to recover after confirmed retirement")
	}
}

func TestGPGDebounceNeverRoundsBelowSixtySeconds(t *testing.T) {
	f := newGPGFixture(t)
	f.reconcile()
	f.now = f.now.Add(500 * time.Millisecond)
	var provider forgev1.ForgejoProvider
	ctx := context.Background()
	if err := f.r.Get(ctx, client.ObjectKey{Namespace: "providers", Name: "shared"}, &provider); err != nil {
		t.Fatal(err)
	}
	provider.Spec.GPGKeys = nil
	if err := f.r.Update(ctx, &provider); err != nil {
		t.Fatal(err)
	}
	f.reconcile()
	f.now = f.now.Add(59500 * time.Millisecond)
	f.reconcile()
	if f.deletes != 0 {
		t.Fatal("timestamp serialization shortened debounce below 60 seconds")
	}
	f.now = f.now.Add(time.Second)
	f.reconcile()
	if f.deletes != 1 {
		t.Fatal("rounded debounce failed to expire")
	}
}

func TestGPGStagedKeyCopiedToActiveStillRetiresPreviousKey(t *testing.T) {
	f := newGPGFixture(t)
	f.rotation()
	old := f.reconcile().Status.KeyID
	f.now = f.now.Add(time.Hour)
	f.failPost = true // Leaves a minted staged key without a promotion deadline.
	f.reconcile()
	f.failPost = false
	secret := f.secret()
	staged, err := credentials.ReadGPG(secret.Data[gpgPendingPrivate], "Renovate", "bot@example.test", "ed25519")
	if err != nil {
		t.Fatal(err)
	}
	writeGPGOutputs(secret, [4]string{"privateKey", "publicKey", "keyID", "fingerprint"}, staged)
	delete(secret.Data, gpgPendingPrivate)
	if err := f.r.Update(context.Background(), secret); err != nil {
		t.Fatal(err)
	}
	key := f.reconcile()
	journal := f.journal()
	if !meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || len(journal.Retiring) != 1 || journal.Retiring[0].KeyID != old || journal.CurrentID != staged.KeyID {
		t.Fatal("staged copy stranded previous minted key")
	}
	f.now = f.now.Add(30 * time.Minute)
	f.reconcile()
	if len(f.journal().Minted) != 1 || f.deletes != 1 {
		t.Fatal("previous minted key failed to retire")
	}
}
