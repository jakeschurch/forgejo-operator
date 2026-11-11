package controller

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	"github.com/jakeschurch/forgejo-operator/internal/credentials"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// 2026-11-11: ownerReferences, CR status and tenant Secret annotations are
// writable by tenants. Only this operator-namespace record proves minting.
// It contains public fingerprints, never private material. Protect this
// namespace with RBAC just as strictly as the operator service account.
type gpgJournal struct {
	Minted    map[string]string `json:"minted"`
	CurrentID string            `json:"currentID,omitempty"`
	PendingID string            `json:"pendingID,omitempty"`
}

func (r *GPGKeyReconciler) journalKey(key *forgev1.ForgejoGPGKey) (client.ObjectKey, error) {
	if r.StateNamespace == "" || key.UID == "" {
		return client.ObjectKey{}, errors.New("operator namespace and CR UID are required for GPG provenance")
	}
	return client.ObjectKey{Namespace: r.StateNamespace, Name: fmt.Sprintf("forgejo-gpg-%x", sha256.Sum256([]byte(key.UID)))}, nil
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
	var record corev1.ConfigMap
	if err := reader.Get(ctx, ref, &record); apierrors.IsNotFound(err) {
		return &gpgJournal{Minted: map[string]string{}}, nil
	} else if err != nil {
		return nil, err
	}
	var journal gpgJournal
	if err := json.Unmarshal([]byte(record.Data["journal"]), &journal); err != nil || journal.Minted == nil {
		return nil, errors.New("invalid operator GPG provenance record")
	}
	return &journal, nil
}

func (r *GPGKeyReconciler) writeGPGJournal(ctx context.Context, key *forgev1.ForgejoGPGKey, journal *gpgJournal) error {
	ref, err := r.journalKey(key)
	if err != nil {
		return err
	}
	reader := r.StateReader
	if reader == nil {
		reader = r.Client
	}
	var record corev1.ConfigMap
	err = reader.Get(ctx, ref, &record)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	data, errJSON := json.Marshal(journal)
	if errJSON != nil {
		return errJSON
	}
	if apierrors.IsNotFound(err) {
		record = corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: ref.Namespace}, Data: map[string]string{"journal": string(data)}}
		return r.Create(ctx, &record)
	}
	record.Data["journal"] = string(data)
	return r.Update(ctx, &record)
}

// Called only with material just generated in this process, before publishing
// either a Secret or a public key. No Secret/status recovery may call this.
func (r *GPGKeyReconciler) mintGPGJournal(ctx context.Context, key *forgev1.ForgejoGPGKey, journal *gpgJournal, material *credentials.GPGKey) error {
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
