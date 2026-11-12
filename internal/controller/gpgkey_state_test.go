package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	"github.com/jakeschurch/forgejo-operator/internal/credentials"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
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

func TestGPGUnauthorizedNamespaceCreatesNoState(t *testing.T) {
	f := newGPGFixture(t)
	ctx := context.Background()
	var provider forgev1.ForgejoProvider
	if err := f.r.Get(ctx, client.ObjectKey{Namespace: "providers", Name: "shared"}, &provider); err != nil {
		t.Fatal(err)
	}
	provider.Spec.GPGKeys.AllowedNamespaces = nil
	if err := f.r.Update(ctx, &provider); err != nil {
		t.Fatal(err)
	}
	f.r.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unauthorized namespace reached Forgejo")
		return nil, nil
	})
	f.reconcile()
	var states forgev1.ForgejoGPGKeyStateList
	if err := f.r.List(ctx, &states); err != nil || len(states.Items) != 0 {
		t.Fatal("unauthorized namespace created state")
	}
}

func TestGPGStateNamespaceMoveAndClockSkew(t *testing.T) {
	for _, skew := range []time.Duration{0, -time.Second, -5 * time.Second} {
		t.Run(skew.String(), func(t *testing.T) {
			f := newGPGFixture(t)
			key := f.reconcile()
			journal := f.journal()
			// Old records may still carry the previous operator namespace annotation.
			journal.record.Annotations["forgejo.jakeschurch.com/gpg-state-operator"] = f.r.StateNamespace
			journal.record.CreationTimestamp = metav1.NewTime(key.CreationTimestamp.Add(skew))
			if err := f.r.Update(context.Background(), journal.record); err != nil {
				t.Fatal(err)
			}
			f.r.StateNamespace = "moved-operator"
			got := f.reconcile()
			if !meta.IsStatusConditionTrue(got.Status.Conditions, "Ready") || got.Status.KeyID != key.Status.KeyID || f.posts != 1 {
				t.Fatal("namespace move or clock skew refused valid state")
			}
			f.admin = true
			f.reconcile()
			if f.deletes != 1 {
				t.Fatal("namespace move blocked administrator revocation")
			}
		})
	}
}

func TestGPGCleanupWithRefusedOrMissingState(t *testing.T) {
	for _, mode := range []string{"refused", "missing"} {
		for _, action := range []string{"delete", "deauthorize", "admin"} {
			t.Run(mode+"/"+action, func(t *testing.T) {
				f := newGPGFixture(t)
				ctx := context.Background()
				key := f.reconcile()
				journal := f.journal()
				if mode == "refused" {
					journal.record.Annotations[gpgSourceUID] = "foreign"
					if err := f.r.Update(ctx, journal.record); err != nil {
						t.Fatal(err)
					}
				} else if err := f.r.Delete(ctx, journal.record); err != nil {
					t.Fatal(err)
				}
				if action == "delete" {
					if err := f.r.Delete(ctx, key); err != nil {
						t.Fatal(err)
					}
					// Empty/refused provenance must not need a provider for deletion.
					if err := f.r.Delete(ctx, &forgev1.ForgejoProvider{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "providers"}}); err != nil {
						t.Fatal(err)
					}
					if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: f.key}); err != nil {
						t.Fatal(err)
					}
					if err := f.r.Get(ctx, f.key, &forgev1.ForgejoGPGKey{}); !apierrors.IsNotFound(err) {
						t.Fatalf("deletion stuck: %v", err)
					}
					if err := f.r.Get(ctx, client.ObjectKeyFromObject(journal.record), &forgev1.ForgejoGPGKeyState{}); !apierrors.IsNotFound(err) {
						t.Fatalf("state retained after deletion: %v", err)
					}
				} else {
					if action == "admin" {
						f.admin = true
					} else {
						var provider forgev1.ForgejoProvider
						if err := f.r.Get(ctx, client.ObjectKey{Namespace: "providers", Name: "shared"}, &provider); err != nil {
							t.Fatal(err)
						}
						provider.Spec.GPGKeys = nil
						if err := f.r.Update(ctx, &provider); err != nil {
							t.Fatal(err)
						}
					}
					got := f.reconcile()
					f.now = f.now.Add(time.Minute)
					got = f.reconcile()
					condition := meta.FindStatusCondition(got.Status.Conditions, "KeyRegistered")
					if condition == nil || condition.Reason != "AuthorizationRevoked" {
						t.Fatalf("cleanup skipped: %+v", got.Status.Conditions)
					}
					var states forgev1.ForgejoGPGKeyStateList
					if err := f.r.List(ctx, &states); err != nil {
						t.Fatal(err)
					}
					if mode == "missing" && len(states.Items) != 0 {
						t.Fatal("cleanup created state")
					}
				}
				if f.deletes != 0 || len(f.keys) != 1 || f.posts != 1 {
					t.Fatal("cleanup acted on unproven keys")
				}
			})
		}
	}
}

func TestGPGSecretDeletionLoopKeepsSigning(t *testing.T) {
	f := newGPGFixture(t)
	f.reconcile()
	for i := 0; i < maxGPGMinted+1; i++ {
		if err := f.r.Delete(context.Background(), f.secret()); err != nil {
			t.Fatal(err)
		}
		key := f.reconcile()
		if !meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || len(f.keys) != i+2 {
			t.Fatalf("recovery %d blocked signing or shortened grace: %+v", i+1, key.Status.Conditions)
		}
	}
	f.now = f.now.Add(gpgGrace)
	f.reconcile()
	if len(f.keys) != 1 || len(f.journal().Minted) != 1 {
		t.Fatal("recovery keys failed to retire")
	}
}

func TestGPGSecretDeletionTotalCeilingAndRecovery(t *testing.T) {
	f := newGPGFixture(t)
	key := f.reconcile()
	journal := f.journal()
	// Seed published history just below the ceiling; the smaller deletion-loop
	// test above exercises repeated real minting. Use normal 50-key pages here
	// to avoid quadratic one-key pagination and its production rate limit.
	for i := 1; i < maxGPGTotalMinted-1; i++ {
		id := fmt.Sprintf("retired-%d", i)
		journal.Minted[id] = id
		journal.Retiring = append(journal.Retiring, forgev1.GPGKeyRetirement{KeyID: id, RemoveAfter: metav1.NewTime(f.now.Add(gpgGrace))})
		f.keys = append(f.keys, remoteGPGKey{ID: int64(100 + i), KeyID: id})
	}
	if err := f.r.writeGPGJournal(context.Background(), key, journal); err != nil {
		t.Fatal(err)
	}
	f.r.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodGet && req.URL.Path == "/api/v1/user/gpg_keys" {
			page, _ := strconv.Atoi(req.URL.Query().Get("page"))
			start := min((page-1)*50, len(f.keys))
			data, _ := json.Marshal(f.keys[start:min(start+50, len(f.keys))])
			return response(200, string(data)), nil
		}
		return f.serve(req)
	})
	if err := f.r.Delete(context.Background(), f.secret()); err != nil {
		t.Fatal(err)
	}
	if key := f.reconcile(); !meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || len(f.journal().Minted) != maxGPGTotalMinted {
		t.Fatalf("recovery below total ceiling failed: %+v", key.Status.Conditions)
	}
	if err := f.r.Delete(context.Background(), f.secret()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		key := f.reconcile()
		if meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || f.posts != 2 || len(f.journal().Minted) != maxGPGTotalMinted || f.deletes != 0 {
			t.Fatal("Secret loss exceeded total ceiling or shortened grace")
		}
		if err := f.r.Get(context.Background(), client.ObjectKey{Namespace: f.key.Namespace, Name: "signing-key"}, &corev1.Secret{}); !apierrors.IsNotFound(err) {
			t.Fatalf("replacement Secret created at ceiling: %v", err)
		}
	}
	f.now = f.now.Add(gpgGrace)
	f.failDelete = true
	f.reconcile()
	if f.posts != 2 || len(f.journal().Minted) != maxGPGTotalMinted {
		t.Fatal("unconfirmed remote retirement freed capacity")
	}
	f.failDelete = false
	key = f.reconcile()
	if !meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || len(f.journal().Minted) != 1 || len(f.keys) != 1 || f.posts != 3 {
		t.Fatal("confirmed retirement did not restore replacement minting")
	}
}

func TestGPGMintJournalEnforcesBothCaps(t *testing.T) {
	for _, retiring := range []bool{false, true} {
		t.Run(fmt.Sprint(retiring), func(t *testing.T) {
			journal := &gpgJournal{GPGKeyStateSpec: forgev1.GPGKeyStateSpec{Minted: map[string]string{}}}
			limit := maxGPGMinted
			if retiring {
				limit = maxGPGTotalMinted
			}
			for i := 0; i < limit; i++ {
				id := fmt.Sprint(i)
				journal.Minted[id] = id
				if retiring {
					journal.Retiring = append(journal.Retiring, forgev1.GPGKeyRetirement{KeyID: id})
				}
			}
			if err := (&GPGKeyReconciler{}).mintGPGJournal(context.Background(), nil, journal, &credentials.GPGKey{KeyID: "new"}); err == nil || len(journal.Minted) != limit || journal.PendingID != "" {
				t.Fatal("mint journal failed to reject at capacity before mutation")
			}
		})
	}
}

func TestGPGRefusesForeignAndPredatingState(t *testing.T) {
	for _, mode := range []string{"foreign_uid", "foreign_name", "foreign_namespace", "predates", "owner_reference"} {
		t.Run(mode, func(t *testing.T) {
			f := newGPGFixture(t)
			var key forgev1.ForgejoGPGKey
			ctx := context.Background()
			if err := f.r.Get(ctx, f.key, &key); err != nil {
				t.Fatal(err)
			}
			ref, _ := f.r.journalKey(&key)
			state := &forgev1.ForgejoGPGKeyState{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, CreationTimestamp: metav1.NewTime(f.now), Annotations: map[string]string{gpgSourceUID: string(key.UID), gpgSourceName: key.Name, gpgSourceNamespace: key.Namespace}}, Spec: forgev1.GPGKeyStateSpec{Minted: map[string]string{"ATTACKER": "FORGED"}, CurrentID: "ATTACKER"}}
			switch mode {
			case "foreign_uid":
				state.Annotations[gpgSourceUID] = "other"
			case "foreign_name":
				state.Annotations[gpgSourceName] = "other"
			case "foreign_namespace":
				state.Annotations[gpgSourceNamespace] = "other"
			case "predates":
				state.CreationTimestamp = metav1.NewTime(f.now.Add(-6 * time.Second))
			case "owner_reference":
				state.OwnerReferences = []metav1.OwnerReference{{UID: key.UID}}
			}
			if err := f.r.Create(ctx, state); err != nil {
				t.Fatal(err)
			}
			f.r.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.Path == "/api/v1/users/renovate" {
					return response(200, `{"is_admin":false}`), nil
				}
				t.Fatal("foreign state reached Forgejo key/email APIs")
				return nil, nil
			})
			got := f.reconcile()
			if meta.IsStatusConditionTrue(got.Status.Conditions, "Ready") {
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

func TestGPGMissingSecretConfirmsPendingRemovalBeforeRemint(t *testing.T) {
	f := newGPGFixture(t)
	ctx := context.Background()
	key := f.reconcile()
	journal := f.journal()
	pending, err := credentials.GenerateGPG(key.Spec.Identity.Name, key.Spec.Identity.Email, "ed25519", f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.r.mintGPGJournal(ctx, key, journal, pending); err != nil {
		t.Fatal(err)
	}
	// Registration succeeded, but Secret staging/publication was lost.
	f.keys = append(f.keys, remoteGPGKey{ID: 99, KeyID: pending.KeyID})
	if err := f.r.Delete(ctx, f.secret()); err != nil {
		t.Fatal(err)
	}
	f.failDelete = true
	got := f.reconcile()
	if meta.IsStatusConditionTrue(got.Status.Conditions, "Ready") || f.posts != 1 || f.journal().PendingID != pending.KeyID {
		t.Fatal("reminted or forgot pending provenance before confirmed removal")
	}
	f.failDelete = false
	got = f.reconcile()
	if !meta.IsStatusConditionTrue(got.Status.Conditions, "Ready") || f.posts != 2 || f.deletes != 1 || f.journal().Minted[pending.KeyID] != "" || len(f.keys) != 2 {
		t.Fatal("pending removal failed or shortened current key grace")
	}
}

func TestGPGRepeatedPublicationFailuresBoundProvenance(t *testing.T) {
	f := newGPGFixture(t)
	f.failPost = true
	for i := 0; i < maxGPGMinted+2; i++ {
		f.reconcile()
	}
	if len(f.journal().Minted) != 1 {
		t.Fatal("unbounded fingerprints")
	}
	f.now = f.now.Add(gpgGrace)
	f.failPost = false
	key := f.reconcile()
	if !meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") || len(f.journal().Minted) != 1 {
		t.Fatal("publication failed to recover after confirmed removal")
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
