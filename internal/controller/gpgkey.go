package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	"github.com/jakeschurch/forgejo-operator/internal/credentials"
	forgeapi "github.com/jakeschurch/forgejo-operator/internal/forgejo"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
)

const gpgStateAnnotation = "forgejo.jakeschurch.com/gpg-state"
const gpgPendingPrivate = "forgejoPendingPrivateKey"
const gpgGrace = 24 * time.Hour
const maxGPGPages = 100

type GPGKeyReconciler struct {
	Reconciler
	// Now is a test seam for rotation and grace deadlines.
	Now func() time.Time
	// StateNamespace identifies the deployment, not a binding on cluster-scoped state.
	StateNamespace string
	StateReader    client.Reader
	Recorder       record.EventRecorder
}

type gpgRetiring struct {
	KeyID       string    `json:"keyID"`
	RemoveAfter time.Time `json:"removeAfter"`
}

// The Secret holds private material and a human-readable lifecycle mirror.
// Only ForgejoGPGKeyState supplies trusted rotation and retirement deadlines.
type gpgState struct {
	CreatedAt time.Time     `json:"createdAt"`
	Retiring  []gpgRetiring `json:"retiring,omitempty"`
}

type remoteGPGKey struct {
	ID    int64  `json:"id"`
	KeyID string `json:"key_id"`
}

const gpgSecretIndex = "gpg.secret"
const gpgProviderIndex = "gpg.provider"
const gpgTokenIndex = "gpg.token"

func gpgSecretRefs(object client.Object) []string {
	key := object.(*forgev1.ForgejoGPGKey)
	return []string{key.Namespace + "/" + key.Spec.SecretRef.Name}
}

func gpgProviderRefs(object client.Object) []string {
	key := object.(*forgev1.ForgejoGPGKey)
	return []string{gpgProviderNS(key) + "/" + key.Spec.ProviderRef}
}

func gpgTokenRefs(object client.Object) []string {
	provider := object.(*forgev1.ForgejoProvider)
	return []string{provider.Namespace + "/" + provider.Spec.TokenSecretRef.Name}
}

func (r *GPGKeyReconciler) SetupWithManager(m ctrl.Manager) error {
	if r.StateNamespace == "" {
		return errors.New("operator namespace is required for GPG provenance")
	}
	r.StateReader = m.GetAPIReader()
	r.Recorder = m.GetEventRecorderFor("forgejo-gpgkey")
	for _, index := range []struct {
		object  client.Object
		field   string
		extract client.IndexerFunc
	}{
		{&forgev1.ForgejoGPGKey{}, gpgSecretIndex, gpgSecretRefs},
		{&forgev1.ForgejoGPGKey{}, gpgProviderIndex, gpgProviderRefs},
		{&forgev1.ForgejoProvider{}, gpgTokenIndex, gpgTokenRefs},
	} {
		if err := m.GetFieldIndexer().IndexField(context.Background(), index.object, index.field, index.extract); err != nil {
			return err
		}
	}
	return ctrl.NewControllerManagedBy(m).
		For(&forgev1.ForgejoGPGKey{}, builder.WithPredicates(primaryResourceChanges())).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.secretRequests)).
		Watches(&forgev1.ForgejoProvider{}, handler.EnqueueRequestsFromMapFunc(r.providerRequests)).Complete(r)
}

func (r *GPGKeyReconciler) secretRequests(ctx context.Context, object client.Object) []ctrl.Request {
	var keys forgev1.ForgejoGPGKeyList
	ref := object.GetNamespace() + "/" + object.GetName()
	if err := r.List(ctx, &keys, client.MatchingFields{gpgSecretIndex: ref}); err != nil {
		return nil
	}
	requests := map[client.ObjectKey]bool{}
	for i := range keys.Items {
		requests[client.ObjectKeyFromObject(&keys.Items[i])] = true
	}
	var providers forgev1.ForgejoProviderList
	if err := r.List(ctx, &providers, client.MatchingFields{gpgTokenIndex: ref}); err != nil {
		return nil
	}
	for i := range providers.Items {
		for _, req := range r.providerRequests(ctx, &providers.Items[i]) {
			requests[req.NamespacedName] = true
		}
	}
	var result []ctrl.Request
	for key := range requests {
		result = append(result, ctrl.Request{NamespacedName: key})
	}
	return result
}

func (r *GPGKeyReconciler) providerRequests(ctx context.Context, object client.Object) []ctrl.Request {
	var keys forgev1.ForgejoGPGKeyList
	if err := r.List(ctx, &keys, client.MatchingFields{gpgProviderIndex: object.GetNamespace() + "/" + object.GetName()}); err != nil {
		return nil
	}
	var requests []ctrl.Request
	for i := range keys.Items {
		requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&keys.Items[i])})
	}
	return requests
}

func gpgProviderNS(key *forgev1.ForgejoGPGKey) string {
	return providerNS(key.Namespace, forgev1.CommonSpec{ProviderNamespace: key.Spec.ProviderNamespace})
}

func (r *GPGKeyReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now().UTC()
	}
	return time.Now().UTC()
}

func gpgCondition(key *forgev1.ForgejoGPGKey, condition string, value metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&key.Status.Conditions, metav1.Condition{Type: condition, Status: value, Reason: reason, Message: message, ObservedGeneration: key.Generation})
}

func (r *GPGKeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var key forgev1.ForgejoGPGKey
	if err := r.Get(ctx, req.NamespacedName, &key); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	// 2026-11-11: both policies need local state cleanup; Orphan never needs
	// provider access to finish deletion.
	if key.DeletionTimestamp.IsZero() && !contains(key.Finalizers, finalizer) {
		key.Finalizers = append(key.Finalizers, finalizer)
		if err := r.Update(ctx, &key); err != nil {
			return ctrl.Result{}, err
		}
	}
	gpgCondition(&key, "EmailVerified", metav1.ConditionUnknown, "NotChecked", "activated account email has not been checked")
	gpgCondition(&key, "KeyRegistered", metav1.ConditionUnknown, "NotChecked", "key registration has not been checked")
	var err error
	if !key.DeletionTimestamp.IsZero() {
		if key.Spec.DeletionPolicy == forgev1.DeletionPolicyDelete {
			var ids []string
			ids, err = r.provenGPGIDs(ctx, &key)
			if err == nil && len(ids) > 0 {
				var api *forgeapi.Client
				api, err = r.providerClient(ctx, gpgProviderNS(&key), key.Spec.ProviderRef)
				if err == nil {
					err = r.removeGPG(ctx, api, &key, ids)
				}
			}
		}
		if err == nil {
			err = r.deleteGPGJournal(ctx, &key)
		}
		if err == nil {
			if !contains(key.Finalizers, finalizer) {
				return ctrl.Result{}, nil
			}
			key.Finalizers = remove(key.Finalizers, finalizer)
			return ctrl.Result{}, r.Update(ctx, &key)
		}
	} else {
		var api *forgeapi.Client
		api, err = r.authorizedGPGClient(ctx, &key)
		if errors.Is(err, errGPGUnauthorized) {
			journal, cleanupErr := r.cleanupGPGJournal(ctx, &key)
			if cleanupErr == nil {
				r.warnGPGMirrors(&key, &corev1.Secret{}, journal)
				key.Status.ManagedKeyIDs = journal.ids()
				if journal.record == nil {
					// No proven keys or state to debounce: revocation is a safe no-op.
				} else if journal.UnauthorizedSince == nil {
					observed := r.now()
					// metav1.Time persists whole seconds. Round upward so
					// serialization can never shorten the 60-second debounce.
					since := metav1.NewTime(observed.Truncate(time.Second))
					if observed.Nanosecond() != 0 {
						since.Time = since.Add(time.Second)
					}
					journal.UnauthorizedSince = &since
					cleanupErr = r.writeGPGJournal(ctx, &key, journal)
				} else if !r.now().Before(journal.UnauthorizedSince.Add(time.Minute)) && !errors.Is(err, errGPGAdmin) {
					// A second observation >=60s later is required for policy revocation.
					// Administrator promotion bypasses the debounce, including first sight.
					cleanupErr = r.revokeGPG(ctx, &key, journal)
				}
				if cleanupErr == nil && errors.Is(err, errGPGAdmin) {
					cleanupErr = r.revokeGPG(ctx, &key, journal)
				}
			}
			if cleanupErr != nil {
				err = fmt.Errorf("authorization revoked; key revocation failed: %w", cleanupErr)
			} else {
				gpgCondition(&key, "KeyRegistered", metav1.ConditionFalse, "AuthorizationRevoked", "management unauthorized; policy revocation requires two observations at least 60s apart; administrators are revoked immediately")
			}
		} else {
			// Authorized or indeterminate observations break the consecutive sequence.
			var journal *gpgJournal
			var stateErr error
			if err == nil {
				journal, stateErr = r.ensureGPGJournal(ctx, &key)
			} else {
				journal, stateErr = r.cleanupGPGJournal(ctx, &key)
			}
			if stateErr == nil && journal.UnauthorizedSince != nil {
				journal.UnauthorizedSince = nil
				stateErr = r.writeGPGJournal(ctx, &key, journal)
			}
			if stateErr != nil {
				err = stateErr
			} else if err == nil {
				err = r.reconcileGPG(ctx, api, &key)
			}
		}
	}
	setStatus(&key.Status.CommonStatus, key.Generation, err)
	if updateErr := r.Status().Update(ctx, &key); updateErr != nil {
		return ctrl.Result{}, client.IgnoreNotFound(updateErr)
	}
	if err != nil {
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	// Forgejo has no key-removal webhook. Poll for remote drift, bounded by the
	// next rotation/retirement deadline; Secrets and providers wake us immediately.
	delay := 10 * time.Minute
	if key.Spec.Rotation != nil && key.Spec.Rotation.After != nil {
		delay = min(delay, key.Spec.Rotation.After.Duration)
	}
	delay = min(delay, gpgGracePeriod(&key))
	return ctrl.Result{RequeueAfter: max(time.Second, delay)}, nil
}

var errGPGUnauthorized = errors.New("GPG management is not authorized")
var errGPGAdmin = fmt.Errorf("%w: site administrator target", errGPGUnauthorized)

// 2026-11-11: authorization precedes email reads, minting and registration.
func (r *GPGKeyReconciler) authorizedGPGClient(ctx context.Context, key *forgev1.ForgejoGPGKey) (*forgeapi.Client, error) {
	var provider forgev1.ForgejoProvider
	if err := r.Get(ctx, client.ObjectKey{Namespace: gpgProviderNS(key), Name: key.Spec.ProviderRef}, &provider); err != nil {
		return nil, err
	}
	policy := provider.Spec.GPGKeys
	var policyErr error
	if policy == nil || !slices.Contains(policy.AllowedUsers, key.Spec.User) {
		policyErr = fmt.Errorf("%w: provider gpgKeys.allowedUsers does not authorize the target user", errGPGUnauthorized)
	} else if key.Namespace != provider.Namespace && !slices.Contains(policy.AllowedNamespaces, key.Namespace) {
		policyErr = fmt.Errorf("%w: provider gpgKeys.allowedNamespaces does not authorize this namespace", errGPGUnauthorized)
	}
	if policyErr != nil {
		journal, err := r.cleanupGPGJournal(ctx, key)
		if err != nil {
			return nil, err
		}
		if len(journal.Minted) == 0 {
			return nil, policyErr
		}
		// For existing managed keys, still detect administrator promotion even
		// when the policy is removed in the same observation. No email/key reads.
	}
	api, err := r.providerClient(ctx, provider.Namespace, provider.Name)
	if err != nil {
		return nil, err
	}
	var user struct {
		IsAdmin *bool `json:"is_admin"`
	}
	if err := api.Do(ctx, http.MethodGet, "users/"+url.PathEscape(key.Spec.User), nil, &user); err != nil {
		return nil, err
	}
	if user.IsAdmin == nil {
		return nil, errors.New("unknown administrator status")
	}
	if *user.IsAdmin {
		return nil, errGPGAdmin
	}
	if policyErr != nil {
		return nil, policyErr
	}
	return api, nil
}

func gpgOutputKeys(spec *forgev1.GPGSecretKeys) ([4]string, error) {
	if spec == nil {
		spec = &forgev1.GPGSecretKeys{}
	}
	keys := [4]string{spec.PrivateKey, spec.PublicKey, spec.KeyID, spec.Fingerprint}
	defaults := [4]string{"privateKey", "publicKey", "keyID", "fingerprint"}
	seen := map[string]bool{gpgPendingPrivate: true}
	for i := range keys {
		if keys[i] == "" {
			keys[i] = defaults[i]
		}
		if seen[keys[i]] {
			return keys, errors.New("Secret output keys must be distinct and cannot use forgejoPendingPrivateKey")
		}
		seen[keys[i]] = true
	}
	return keys, nil
}

func (r *GPGKeyReconciler) reconcileGPG(ctx context.Context, api *forgeapi.Client, key *forgev1.ForgejoGPGKey) error {
	outputs, err := gpgOutputKeys(key.Spec.SecretRef.Keys)
	if err != nil {
		return err
	}
	if key.Spec.Rotation != nil {
		if key.Spec.Rotation.After != nil && key.Spec.Rotation.After.Duration <= 0 {
			return errors.New("rotation.after must be positive")
		}
		if key.Spec.Rotation.GracePeriod != nil && key.Spec.Rotation.GracePeriod.Duration <= 0 {
			return errors.New("rotation.gracePeriod must be positive")
		}
	}
	var owners forgev1.ForgejoGPGKeyList
	if err := r.List(ctx, &owners, client.InNamespace(key.Namespace)); err != nil {
		return err
	}
	for _, other := range owners.Items {
		if other.Name != key.Name && other.Spec.SecretRef.Name == key.Spec.SecretRef.Name {
			return errors.New("Secret is already claimed by another ForgejoGPGKey")
		}
	}
	var emails []struct {
		Email    string `json:"email"`
		Verified bool   `json:"verified"`
	}
	if err := api.DoSudo(ctx, http.MethodGet, "user/emails", key.Spec.User, nil, &emails); err != nil {
		gpgCondition(key, "EmailVerified", metav1.ConditionFalse, "EmailCheckFailed", "cannot read target account emails; provider requires a site administrator token")
		return err
	}
	verified := false
	for _, email := range emails {
		if strings.EqualFold(email.Email, key.Spec.Identity.Email) && email.Verified {
			verified = true
		}
	}
	if !verified {
		gpgCondition(key, "EmailVerified", metav1.ConditionFalse, "EmailNotActivated", "spec.identity.email must be an activated email of spec.user")
		return errors.New("signing identity email is not activated on the target Forgejo account")
	}
	gpgCondition(key, "EmailVerified", metav1.ConditionTrue, "EmailActivated", "signing identity email is activated on the target account")
	var secret corev1.Secret
	err = r.Get(ctx, client.ObjectKey{Namespace: key.Namespace, Name: key.Spec.SecretRef.Name}, &secret)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	secretMissing := apierrors.IsNotFound(err)
	journal, err := r.readGPGJournal(ctx, key)
	if err != nil {
		return err
	}
	if !secretMissing && len(journal.Minted) == 0 {
		return r.gpgTampered(key)
	}
	r.warnGPGMirrors(key, &secret, journal)
	state := journal.lifecycle()
	if secretMissing {
		// 2026-11-11: private material for a pending mint was never published or
		// has been lost. Confirm removal before forgetting it and retrying.
		if id := journal.PendingID; id != "" {
			if err := r.removeGPG(ctx, api, key, []string{id}); err != nil {
				return err
			}
			delete(journal.Minted, id)
			journal.PendingID = ""
			state.Retiring = slices.DeleteFunc(state.Retiring, func(old gpgRetiring) bool { return old.KeyID == id })
		}
		// Persist cleanup of every not-yet-removed key, independently of status.
		for id := range journal.Minted {
			if !slices.ContainsFunc(state.Retiring, func(old gpgRetiring) bool { return old.KeyID == id }) {
				state.Retiring = append(state.Retiring, gpgRetiring{KeyID: id, RemoveAfter: r.now().Add(gpgGracePeriod(key))})
			}
		}
		journal.setLifecycle(state)
		if err := r.writeGPGJournal(ctx, key, journal); err != nil {
			return err
		}
		if err := r.retireGPG(ctx, api, key, journal, ""); err != nil {
			return err
		}
		state = journal.lifecycle()
		if err := journal.mintLimit(); err != nil {
			return err
		}
		material, err := credentials.GenerateGPG(key.Spec.Identity.Name, key.Spec.Identity.Email, key.Spec.Algorithm, r.now())
		if err != nil {
			return err
		}
		if err := r.mintGPGJournal(ctx, key, journal, material); err != nil {
			return err
		}
		state.CreatedAt = r.now()
		journal.setLifecycle(state)
		if err := r.writeGPGJournal(ctx, key, journal); err != nil {
			return err
		}
		secret = corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: key.Spec.SecretRef.Name, Namespace: key.Namespace}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{}}
		if err := ctrl.SetControllerReference(key, &secret, r.Scheme()); err != nil {
			return err
		}
		writeGPGOutputs(&secret, outputs, material)
		writeGPGState(&secret, state)
		if _, err := r.registerGPG(ctx, api, key, material); err != nil {
			gpgCondition(key, "KeyRegistered", metav1.ConditionFalse, "RegistrationFailed", "public key registration failed")
			return err
		}
		if err := r.Create(ctx, &secret); err != nil {
			return err
		}
	} else {
		if !metav1.IsControlledBy(&secret, key) {
			return errors.New("referenced Secret is not controlled by this ForgejoGPGKey; refusing adoption")
		}
		for _, owner := range secret.OwnerReferences {
			if owner.UID != key.UID {
				return errors.New("referenced Secret belongs to another owner")
			}
		}
	}
	material, err := credentials.ReadGPG(secret.Data[outputs[0]], key.Spec.Identity.Name, key.Spec.Identity.Email, key.Spec.Algorithm)
	if err != nil || !journal.accepts(material) {
		return r.gpgTampered(key)
	}
	if len(secret.Data[gpgPendingPrivate]) != 0 {
		pending, err := credentials.ReadGPG(secret.Data[gpgPendingPrivate], key.Spec.Identity.Name, key.Spec.Identity.Email, key.Spec.Algorithm)
		if err != nil || pending.KeyID != journal.PendingID || !journal.accepts(pending) || pending.KeyID == material.KeyID {
			return r.gpgTampered(key)
		}
	} else if journal.PendingID != "" && material.KeyID != journal.PendingID {
		// Mint persisted but staging failed (or the staged private key was lost).
		// Confirm remote removal before forgetting its fingerprint.
		id := journal.PendingID
		if err := r.removeGPG(ctx, api, key, []string{id}); err != nil {
			return err
		}
		delete(journal.Minted, id)
		journal.PendingID = ""
		state.Retiring = slices.DeleteFunc(state.Retiring, func(old gpgRetiring) bool { return old.KeyID == id || old.KeyID == material.KeyID })
		journal.setLifecycle(state)
		if err := r.writeGPGJournal(ctx, key, journal); err != nil {
			return err
		}
	}
	// Complete a promotion whose Secret update succeeded before a process crash.
	if material.KeyID == journal.PendingID {
		// A tenant can copy the staged private key into the active outputs.
		// It is minted, but only protected state may schedule its transition.
		if journal.CurrentID != "" && !slices.ContainsFunc(state.Retiring, func(old gpgRetiring) bool { return old.KeyID == journal.CurrentID }) {
			state.Retiring = append(state.Retiring, gpgRetiring{KeyID: journal.CurrentID, RemoveAfter: r.now().Add(gpgGracePeriod(key))})
			state.CreatedAt = r.now()
			journal.setLifecycle(state)
		}
		journal.CurrentID, journal.PendingID = material.KeyID, ""
		if err := r.writeGPGJournal(ctx, key, journal); err != nil {
			return err
		}
	}
	remote, err := r.registerGPG(ctx, api, key, material)
	if err != nil {
		gpgCondition(key, "KeyRegistered", metav1.ConditionFalse, "RegistrationFailed", "public key registration failed")
		return err
	}
	if err := r.retireGPG(ctx, api, key, journal, material.KeyID); err != nil {
		return err
	}
	state = journal.lifecycle()
	due := key.Spec.Rotation != nil && key.Spec.Rotation.After != nil && !r.now().Before(state.CreatedAt.Add(key.Spec.Rotation.After.Duration))
	if due && len(state.Retiring) == 0 && len(secret.Data[gpgPendingPrivate]) == 0 {
		if err := journal.mintLimit(); err != nil {
			return err
		}
		pending, err := credentials.GenerateGPG(key.Spec.Identity.Name, key.Spec.Identity.Email, key.Spec.Algorithm, r.now())
		if err != nil {
			return err
		}
		if err := r.mintGPGJournal(ctx, key, journal, pending); err != nil {
			return err
		}
		secret.Data[gpgPendingPrivate] = pending.Private
		if err := r.Update(ctx, &secret); err != nil {
			return err
		}
	}
	if len(secret.Data[gpgPendingPrivate]) != 0 {
		pending, err := credentials.ReadGPG(secret.Data[gpgPendingPrivate], key.Spec.Identity.Name, key.Spec.Identity.Email, key.Spec.Algorithm)
		if err != nil || pending.KeyID != journal.PendingID || !journal.accepts(pending) || pending.KeyID == material.KeyID {
			return r.gpgTampered(key)
		}
		remote, err = r.registerGPG(ctx, api, key, pending)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(state.Retiring, func(old gpgRetiring) bool { return old.KeyID == material.KeyID }) {
			state.Retiring = append(state.Retiring, gpgRetiring{KeyID: material.KeyID, RemoveAfter: r.now().Add(gpgGracePeriod(key))})
			state.CreatedAt = r.now()
			journal.setLifecycle(state)
			// Deadlines precede publication. Retries never extend or shorten grace.
			if err := r.writeGPGJournal(ctx, key, journal); err != nil {
				return err
			}
		}
		writeGPGOutputs(&secret, outputs, pending)
		delete(secret.Data, gpgPendingPrivate)
		writeGPGState(&secret, state)
		if err := r.Update(ctx, &secret); err != nil {
			return err
		}
		material = pending
		journal.CurrentID, journal.PendingID = material.KeyID, ""
		if err := r.writeGPGJournal(ctx, key, journal); err != nil {
			return err
		}
	}
	// Repair tenant-writable mirrors from protected state, never the reverse.
	before := secret.Annotations[gpgStateAnnotation]
	writeGPGState(&secret, journal.lifecycle())
	if before != secret.Annotations[gpgStateAnnotation] || !gpgOutputsMatch(&secret, outputs, material) {
		writeGPGOutputs(&secret, outputs, material)
		if err := r.Update(ctx, &secret); err != nil {
			return err
		}
	}
	key.Status.KeyID, key.Status.Fingerprint, key.Status.RemoteID = material.KeyID, material.Fingerprint, strconv.FormatInt(remote, 10)
	key.Status.GeneratedSecrets = []corev1.LocalObjectReference{{Name: secret.Name}}
	key.Status.ManagedKeyIDs = journal.ids()

	gpgCondition(key, "KeyRegistered", metav1.ConditionTrue, "Registered", "public signing key is registered on the target account")
	return nil
}

func gpgGracePeriod(key *forgev1.ForgejoGPGKey) time.Duration {
	if key.Spec.Rotation != nil && key.Spec.Rotation.GracePeriod != nil {
		return key.Spec.Rotation.GracePeriod.Duration
	}
	return gpgGrace
}

func writeGPGState(secret *corev1.Secret, state gpgState) {
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	data, _ := json.Marshal(state)
	secret.Annotations[gpgStateAnnotation] = string(data)
}

func writeGPGOutputs(secret *corev1.Secret, outputs [4]string, material *credentials.GPGKey) {
	secret.Data[outputs[0]], secret.Data[outputs[1]] = material.Private, material.Public
	secret.Data[outputs[2]], secret.Data[outputs[3]] = []byte(material.KeyID), []byte(material.Fingerprint)
}

func gpgOutputsMatch(secret *corev1.Secret, outputs [4]string, material *credentials.GPGKey) bool {
	return string(secret.Data[outputs[1]]) == string(material.Public) && string(secret.Data[outputs[2]]) == material.KeyID && string(secret.Data[outputs[3]]) == material.Fingerprint
}

func listGPG(ctx context.Context, api *forgeapi.Client, user string) ([]remoteGPGKey, error) {
	var all []remoteGPGKey
	lastFirstID := int64(0)
	for page := 1; page <= maxGPGPages; page++ {
		var keys []remoteGPGKey
		// Forgejo may cap limit below the request; only an empty page ends listing.
		if err := api.DoSudo(ctx, http.MethodGet, fmt.Sprintf("user/gpg_keys?limit=50&page=%d", page), user, nil, &keys); err != nil {
			return nil, err
		}
		if len(keys) == 0 {
			return all, nil
		}
		if keys[0].ID == lastFirstID {
			return nil, errors.New("Forgejo GPG listing repeated a page")
		}
		lastFirstID = keys[0].ID
		all = append(all, keys...)
	}
	return nil, errors.New("Forgejo GPG listing exceeded the page limit")
}

func (r *GPGKeyReconciler) registerGPG(ctx context.Context, api *forgeapi.Client, key *forgev1.ForgejoGPGKey, material *credentials.GPGKey) (int64, error) {
	journal, err := r.readGPGJournal(ctx, key)
	if err != nil {
		return 0, err
	}
	if !journal.accepts(material) {
		return 0, r.gpgTampered(key)
	}

	keys, err := listGPG(ctx, api, key.Spec.User)
	if err != nil {
		return 0, err
	}
	for _, remote := range keys {
		if strings.EqualFold(remote.KeyID, material.KeyID) {
			return remote.ID, nil
		}
	}
	var created remoteGPGKey
	err = api.DoSudo(ctx, http.MethodPost, "user/gpg_keys", key.Spec.User, map[string]string{"armored_public_key": string(material.Public)}, &created)
	if err != nil {
		return 0, err
	}
	if created.ID == 0 || !strings.EqualFold(created.KeyID, material.KeyID) {
		return 0, errors.New("Forgejo returned unexpected registered key identity")
	}
	return created.ID, nil
}

func (r *GPGKeyReconciler) removeGPG(ctx context.Context, api *forgeapi.Client, key *forgev1.ForgejoGPGKey, ids []string) error {
	journal, err := r.readGPGJournal(ctx, key)
	if err != nil {
		return err
	}
	if err := journal.validateIDs(ids); err != nil {
		return err
	}
	keys, err := listGPG(ctx, api, key.Spec.User)
	if isNotFound(err) {
		return nil
	} // Deleted accounts no longer own any keys.
	if err != nil {
		return err
	}
	for _, remote := range keys {
		if !slices.ContainsFunc(ids, func(id string) bool { return strings.EqualFold(id, remote.KeyID) }) {
			continue
		}
		if err := api.DoSudo(ctx, http.MethodDelete, "user/gpg_keys/"+strconv.FormatInt(remote.ID, 10), key.Spec.User, nil, nil); err != nil && !isNotFound(err) {
			return err
		}
	}
	return nil
}

// The protected journal remains authoritative when tenant-writable status is lost.
func (r *GPGKeyReconciler) provenGPGIDs(ctx context.Context, key *forgev1.ForgejoGPGKey) ([]string, error) {
	journal, err := r.cleanupGPGJournal(ctx, key)
	if err != nil {
		return nil, err
	}
	// Tenant status cannot expand the delete set or block proven cleanup.
	return journal.ids(), nil
}
