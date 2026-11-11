package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	"github.com/jakeschurch/forgejo-operator/internal/credentials"
	forgeapi "github.com/jakeschurch/forgejo-operator/internal/forgejo"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// 2026-11-11: RBAC on this dedicated cluster-scoped resource is the trust
// boundary. ConfigMap/Secret writers (including reflectors) cannot mint state.
const gpgSourceUID = "forgejo.jakeschurch.com/gpg-source-uid"
const gpgSourceName = "forgejo.jakeschurch.com/gpg-source-name"
const gpgSourceNamespace = "forgejo.jakeschurch.com/gpg-source-namespace"
const maxGPGMinted = 8

var errGPGStateRefused = errors.New("refusing foreign or pre-existing GPG provenance state")

type gpgJournal struct {
	forgev1.GPGKeyStateSpec
	record *forgev1.ForgejoGPGKeyState
}

func (r *GPGKeyReconciler) journalKey(key *forgev1.ForgejoGPGKey) (client.ObjectKey, error) {
	if r.StateNamespace == "" || key.UID == "" {
		return client.ObjectKey{}, errors.New("operator namespace and CR UID are required for GPG provenance")
	}
	return client.ObjectKey{Name: fmt.Sprintf("forgejo-gpg-%x", sha256.Sum256([]byte(key.UID)))}, nil
}

func (r *GPGKeyReconciler) readGPGJournal(ctx context.Context, key *forgev1.ForgejoGPGKey) (*gpgJournal, error) {
	ref, err := r.journalKey(key)
	if err != nil {
		return nil, err
	}
	reader := r.StateReader
	if reader == nil {
		reader = r.Client
	}
	var record forgev1.ForgejoGPGKeyState
	if err := reader.Get(ctx, ref, &record); err != nil {
		return nil, err
	}
	// Namespaced owners on cluster objects are invalid in Kubernetes. Bind the
	// source through annotations instead; no foreign owner references are allowed.
	if record.Annotations[gpgSourceUID] != string(key.UID) || record.Annotations[gpgSourceName] != key.Name || record.Annotations[gpgSourceNamespace] != key.Namespace || len(record.OwnerReferences) != 0 || record.CreationTimestamp.IsZero() || record.CreationTimestamp.Time.Before(key.CreationTimestamp.Add(-5*time.Second)) || !record.DeletionTimestamp.IsZero() {
		return nil, errGPGStateRefused
	}
	if record.Spec.Minted == nil {
		record.Spec.Minted = map[string]string{}
	}
	return &gpgJournal{GPGKeyStateSpec: *record.Spec.DeepCopy(), record: &record}, nil
}

// 2026-11-11: reserve cluster-scoped state only after creation authorization.
func (r *GPGKeyReconciler) ensureGPGJournal(ctx context.Context, key *forgev1.ForgejoGPGKey) (*gpgJournal, error) {
	journal, err := r.readGPGJournal(ctx, key)
	if !apierrors.IsNotFound(err) {
		return journal, err
	}
	ref, err := r.journalKey(key)
	if err != nil {
		return nil, err
	}
	record := &forgev1.ForgejoGPGKeyState{ObjectMeta: metav1.ObjectMeta{
		Name: ref.Name, CreationTimestamp: metav1.Now(),
		Annotations: map[string]string{gpgSourceUID: string(key.UID), gpgSourceName: key.Name, gpgSourceNamespace: key.Namespace},
	}, Spec: forgev1.GPGKeyStateSpec{Minted: map[string]string{}}}
	if err := r.Create(ctx, record); err != nil {
		return nil, err
	}
	return &gpgJournal{GPGKeyStateSpec: *record.Spec.DeepCopy(), record: record}, nil
}

// Refused or missing provenance proves no IDs. Cleanup must not adopt mirrors,
// create state, or let those records wedge revocation and finalizer removal.
func (r *GPGKeyReconciler) cleanupGPGJournal(ctx context.Context, key *forgev1.ForgejoGPGKey) (*gpgJournal, error) {
	journal, err := r.readGPGJournal(ctx, key)
	if apierrors.IsNotFound(err) || errors.Is(err, errGPGStateRefused) {
		return &gpgJournal{GPGKeyStateSpec: forgev1.GPGKeyStateSpec{Minted: map[string]string{}}}, nil
	}
	return journal, err
}

func (r *GPGKeyReconciler) deleteGPGJournal(ctx context.Context, key *forgev1.ForgejoGPGKey) error {
	ref, err := r.journalKey(key)
	if err != nil {
		return err
	}
	return client.IgnoreNotFound(r.Delete(ctx, &forgev1.ForgejoGPGKeyState{ObjectMeta: metav1.ObjectMeta{Name: ref.Name}}))
}

func (r *GPGKeyReconciler) writeGPGJournal(ctx context.Context, key *forgev1.ForgejoGPGKey, journal *gpgJournal) error {
	// Use the resourceVersion read with this transaction: a stale writer must
	// conflict, never overwrite newer provenance or lifecycle deadlines.
	record := journal.record.DeepCopy()
	record.Spec = *journal.GPGKeyStateSpec.DeepCopy()
	if err := r.Update(ctx, record); err != nil {
		return err
	}
	journal.record = record
	return nil
}

func (j *gpgJournal) lifecycle() gpgState {
	state := gpgState{CreatedAt: j.CreatedAt.Time.UTC()}
	for _, old := range j.Retiring {
		state.Retiring = append(state.Retiring, gpgRetiring{KeyID: old.KeyID, RemoveAfter: old.RemoveAfter.Time.UTC()})
	}
	return state
}

func (j *gpgJournal) setLifecycle(state gpgState) {
	j.CreatedAt = metav1.NewTime(state.CreatedAt)
	j.Retiring = nil
	for _, old := range state.Retiring {
		j.Retiring = append(j.Retiring, forgev1.GPGKeyRetirement{KeyID: old.KeyID, RemoveAfter: metav1.NewTime(old.RemoveAfter)})
	}
}

// Recovery must retain old published keys for grace without exhausting minting
// capacity. Never-staged pending keys are removed before another recovery mint.
func (j *gpgJournal) activeMinted() int {
	count := 0
	for id := range j.Minted {
		if !slices.ContainsFunc(j.Retiring, func(old forgev1.GPGKeyRetirement) bool { return old.KeyID == id }) {
			count++
		}
	}
	return count
}

// Called only with material just generated in this process, before publishing
// either a Secret or a public key. No Secret/status recovery may call this.
func (r *GPGKeyReconciler) mintGPGJournal(ctx context.Context, key *forgev1.ForgejoGPGKey, journal *gpgJournal, material *credentials.GPGKey) error {
	if journal.activeMinted() >= maxGPGMinted {
		return errors.New("GPG minting limit reached; waiting for retirement")
	}
	journal.Minted[material.KeyID] = material.Fingerprint
	journal.PendingID = material.KeyID
	return r.writeGPGJournal(ctx, key, journal)
}

func (j *gpgJournal) accepts(material *credentials.GPGKey) bool {
	return (material.KeyID == j.CurrentID || material.KeyID == j.PendingID) && j.Minted[material.KeyID] == material.Fingerprint
}

func (j *gpgJournal) validateIDs(ids []string) error {
	for _, id := range ids {
		if j.Minted[id] == "" {
			return errors.New("refusing GPG journal entry without operator minting provenance")
		}
	}
	return nil
}

func (r *GPGKeyReconciler) gpgTampered(key *forgev1.ForgejoGPGKey) error {
	const message = "Secret tampered or not minted by this operator; delete the Secret to regenerate signing credentials"
	gpgCondition(key, "KeyRegistered", metav1.ConditionFalse, "SecretTampered", message)
	if r.Recorder != nil {
		r.Recorder.Event(key, corev1.EventTypeWarning, "SecretTampered", message)
	}
	return errors.New(message)
}

func (j *gpgJournal) ids() []string {
	ids := make([]string, 0, len(j.Minted))
	for id := range j.Minted {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

func (r *GPGKeyReconciler) warnGPGMirrors(key *forgev1.ForgejoGPGKey, secret *corev1.Secret, journal *gpgJournal) {
	unknown := journal.validateIDs(key.Status.ManagedKeyIDs) != nil || (key.Status.KeyID != "" && journal.Minted[key.Status.KeyID] == "")
	var mirror gpgState
	if raw := secret.Annotations[gpgStateAnnotation]; raw != "" {
		if json.Unmarshal([]byte(raw), &mirror) != nil {
			unknown = true
		}
		for _, old := range mirror.Retiring {
			if journal.Minted[old.KeyID] == "" {
				unknown = true
			}
		}
	}
	if unknown && r.Recorder != nil {
		r.Recorder.Event(key, corev1.EventTypeWarning, "UntrustedGPGMirror", "ignored unknown GPG IDs or invalid lifecycle mirror; restoring from protected state")
	}
}

// Prune only after idempotent remote removal succeeds.
func (r *GPGKeyReconciler) retireGPG(ctx context.Context, api *forgeapi.Client, key *forgev1.ForgejoGPGKey, journal *gpgJournal, current string) error {
	for _, old := range slices.Clone(journal.Retiring) {
		if old.KeyID == current || (current != "" && old.KeyID == journal.PendingID) || r.now().Before(old.RemoveAfter.Time) {
			continue
		}
		if err := r.removeGPG(ctx, api, key, []string{old.KeyID}); err != nil {
			return err
		}
		delete(journal.Minted, old.KeyID)
		journal.Retiring = slices.DeleteFunc(journal.Retiring, func(v forgev1.GPGKeyRetirement) bool { return v.KeyID == old.KeyID })
		if journal.CurrentID == old.KeyID {
			journal.CurrentID = ""
		}
		if journal.PendingID == old.KeyID {
			journal.PendingID = ""
		}
		if err := r.writeGPGJournal(ctx, key, journal); err != nil {
			return err
		}
	}
	return nil
}

func (r *GPGKeyReconciler) revokeGPG(ctx context.Context, key *forgev1.ForgejoGPGKey, journal *gpgJournal) error {
	ids := journal.ids()
	if len(ids) == 0 {
		return nil
	}
	api, err := r.providerClient(ctx, gpgProviderNS(key), key.Spec.ProviderRef)
	if err != nil {
		return err
	}
	if err := r.removeGPG(ctx, api, key, ids); err != nil {
		return err
	}
	// Current/staged fingerprints still authenticate local private material if
	// authorization returns. Removed historical keys must never be re-armed.
	for id := range journal.Minted {
		if id != journal.CurrentID && id != journal.PendingID {
			delete(journal.Minted, id)
		}
	}
	journal.Retiring = nil
	key.Status.ManagedKeyIDs = journal.ids()
	return r.writeGPGJournal(ctx, key, journal)
}
