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
}

type gpgRetiring struct {
	KeyID       string    `json:"keyID"`
	RemoveAfter time.Time `json:"removeAfter"`
}

// The Secret is the transaction record: staging never changes the mounted key.
// Promotion atomically replaces its four outputs and records retirement deadlines.
type gpgState struct {
	CreatedAt time.Time     `json:"createdAt"`
	Retiring  []gpgRetiring `json:"retiring,omitempty"`
}

type remoteGPGKey struct {
	ID    int64  `json:"id"`
	KeyID string `json:"key_id"`
}

func (r *GPGKeyReconciler) SetupWithManager(m ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(m).
		For(&forgev1.ForgejoGPGKey{}, builder.WithPredicates(primaryResourceChanges())).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.secretRequests)).
		Watches(&forgev1.ForgejoProvider{}, handler.EnqueueRequestsFromMapFunc(r.providerRequests)).Complete(r)
}

func (r *GPGKeyReconciler) secretRequests(ctx context.Context, object client.Object) []ctrl.Request {
	var keys forgev1.ForgejoGPGKeyList
	if err := r.List(ctx, &keys); err != nil {
		return nil
	}
	var providers forgev1.ForgejoProviderList
	if err := r.List(ctx, &providers, client.InNamespace(object.GetNamespace())); err != nil {
		return nil
	}
	var requests []ctrl.Request
	for _, key := range keys.Items {
		matches := key.Namespace == object.GetNamespace() && key.Spec.SecretRef.Name == object.GetName()
		for _, provider := range providers.Items {
			if gpgProviderNS(&key) == provider.Namespace && key.Spec.ProviderRef == provider.Name && provider.Spec.TokenSecretRef.Name == object.GetName() {
				matches = true
			}
		}
		if matches {
			requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&key)})
		}
	}
	return requests
}

func (r *GPGKeyReconciler) providerRequests(ctx context.Context, object client.Object) []ctrl.Request {
	var keys forgev1.ForgejoGPGKeyList
	if err := r.List(ctx, &keys); err != nil {
		return nil
	}
	var requests []ctrl.Request
	for _, key := range keys.Items {
		if gpgProviderNS(&key) == object.GetNamespace() && key.Spec.ProviderRef == object.GetName() {
			requests = append(requests, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(&key)})
		}
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
	// 2026-11-11: Orphan must remain deletable without a working provider.
	if key.Spec.DeletionPolicy != forgev1.DeletionPolicyDelete && contains(key.Finalizers, finalizer) {
		key.Finalizers = remove(key.Finalizers, finalizer)
		if err := r.Update(ctx, &key); err != nil {
			return ctrl.Result{}, err
		}
	}
	if !key.DeletionTimestamp.IsZero() && !contains(key.Finalizers, finalizer) {
		return ctrl.Result{}, nil
	}
	if key.DeletionTimestamp.IsZero() && key.Spec.DeletionPolicy == forgev1.DeletionPolicyDelete && !contains(key.Finalizers, finalizer) {
		key.Finalizers = append(key.Finalizers, finalizer)
		if err := r.Update(ctx, &key); err != nil {
			return ctrl.Result{}, err
		}
	}
	gpgCondition(&key, "EmailVerified", metav1.ConditionUnknown, "NotChecked", "activated account email has not been checked")
	gpgCondition(&key, "KeyRegistered", metav1.ConditionUnknown, "NotChecked", "key registration has not been checked")
	api, err := r.authorizedGPGClient(ctx, &key)
	if err == nil && !key.DeletionTimestamp.IsZero() {
		if !contains(key.Finalizers, finalizer) {
			return ctrl.Result{}, nil
		}
		err = r.deleteGPGKeys(ctx, api, &key)
		if err == nil {
			key.Finalizers = remove(key.Finalizers, finalizer)
			return ctrl.Result{}, r.Update(ctx, &key)
		}
	} else if err == nil {
		err = r.reconcileGPG(ctx, api, &key)
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

// 2026-11-11: authorization precedes all Sudo, email and key operations.
func (r *GPGKeyReconciler) authorizedGPGClient(ctx context.Context, key *forgev1.ForgejoGPGKey) (*forgeapi.Client, error) {
	var provider forgev1.ForgejoProvider
	if err := r.Get(ctx, client.ObjectKey{Namespace: gpgProviderNS(key), Name: key.Spec.ProviderRef}, &provider); err != nil {
		return nil, err
	}
	policy := provider.Spec.GPGKeys
	if policy == nil || !slices.Contains(policy.AllowedUsers, key.Spec.User) {
		return nil, errors.New("provider gpgKeys.allowedUsers does not authorize the target user")
	}
	if key.Namespace != provider.Namespace && !slices.Contains(policy.AllowedNamespaces, key.Namespace) {
		return nil, errors.New("provider gpgKeys.allowedNamespaces does not authorize this namespace")
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
	if user.IsAdmin == nil || *user.IsAdmin {
		return nil, errors.New("GPG key management refuses site administrators or unknown administrator status")
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
	state := gpgState{}
	if apierrors.IsNotFound(err) {
		material, err := credentials.GenerateGPG(key.Spec.Identity.Name, key.Spec.Identity.Email, key.Spec.Algorithm, r.now())
		if err != nil {
			return err
		}
		secret = corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: key.Spec.SecretRef.Name, Namespace: key.Namespace}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{}}
		if err := ctrl.SetControllerReference(key, &secret, r.Scheme()); err != nil {
			return err
		}
		state.CreatedAt = r.now()
		// Secret loss does not lose the remote-key cleanup journal.
		for _, id := range key.Status.ManagedKeyIDs {
			state.Retiring = append(state.Retiring, gpgRetiring{KeyID: id, RemoveAfter: r.now().Add(gpgGracePeriod(key))})
		}
		writeGPGOutputs(&secret, outputs, material)
		writeGPGState(&secret, state)
		// Publish only registered credentials, including on Secret-loss recovery.
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
		if err := json.Unmarshal([]byte(secret.Annotations[gpgStateAnnotation]), &state); err != nil && secret.Annotations[gpgStateAnnotation] != "" {
			return errors.New("invalid GPG Secret lifecycle state")
		}
	}
	material, err := credentials.ReadGPG(secret.Data[outputs[0]], key.Spec.Identity.Name, key.Spec.Identity.Email, key.Spec.Algorithm)
	if err != nil {
		return err
	}
	pendingID := ""
	if len(secret.Data[gpgPendingPrivate]) != 0 {
		pending, err := credentials.ReadGPG(secret.Data[gpgPendingPrivate], key.Spec.Identity.Name, key.Spec.Identity.Email, key.Spec.Algorithm)
		if err != nil {
			return err
		}
		pendingID = pending.KeyID
		if pendingID == material.KeyID {
			return errors.New("staged key must differ from the current signing key")
		}
	}
	stateChanged := false
	// A restored owned Secret can recover a lost status journal, but only for
	// retirement entries that still exist on this user's remote account.
	if len(key.Status.ManagedKeyIDs) == 0 && len(state.Retiring) > 0 {
		remote, err := listGPG(ctx, api, key.Spec.User)
		if err != nil {
			return err
		}
		retiring := make([]gpgRetiring, 0, len(state.Retiring))
		for _, old := range state.Retiring {
			if old.KeyID == material.KeyID || old.KeyID == pendingID {
				return errors.New("Secret retirement state must reference only previous keys")
			}
			if slices.ContainsFunc(remote, func(k remoteGPGKey) bool { return strings.EqualFold(k.KeyID, old.KeyID) }) {
				key.Status.ManagedKeyIDs = append(key.Status.ManagedKeyIDs, old.KeyID)
				retiring = append(retiring, old)
			}
		}
		state.Retiring = retiring
		stateChanged = true
	}
	for _, old := range state.Retiring {
		if old.KeyID == material.KeyID || old.KeyID == pendingID || !slices.Contains(key.Status.ManagedKeyIDs, old.KeyID) {
			return errors.New("Secret retirement state must reference only journaled previous keys")
		}
	}
	for _, id := range key.Status.ManagedKeyIDs {
		if id == material.KeyID || id == pendingID || slices.ContainsFunc(state.Retiring, func(old gpgRetiring) bool { return old.KeyID == id }) {
			continue
		}
		state.Retiring = append(state.Retiring, gpgRetiring{KeyID: id, RemoveAfter: r.now().Add(gpgGracePeriod(key))})
		stateChanged = true
	}
	if stateChanged || state.CreatedAt.IsZero() || !gpgOutputsMatch(&secret, outputs, material) {
		if err := ctrl.SetControllerReference(key, &secret, r.Scheme()); err != nil {
			return err
		}
		if state.CreatedAt.IsZero() {
			state.CreatedAt = material.CreatedAt
		}
		writeGPGOutputs(&secret, outputs, material)
		writeGPGState(&secret, state)
		if err := r.Update(ctx, &secret); err != nil {
			return err
		}
	}
	remote, err := r.registerGPG(ctx, api, key, material)
	if err != nil {
		gpgCondition(key, "KeyRegistered", metav1.ConditionFalse, "RegistrationFailed", "public key registration failed")
		return err
	}
	key.Status.KeyID, key.Status.Fingerprint, key.Status.RemoteID = material.KeyID, material.Fingerprint, strconv.FormatInt(remote, 10)
	key.Status.GeneratedSecrets = []corev1.LocalObjectReference{{Name: secret.Name}}
	// Finish retirement before starting a new rotation. Delete is idempotent and
	// deadlines are persisted before promotion, so all crash windows are replayable.
	for len(state.Retiring) > 0 && !r.now().Before(state.Retiring[0].RemoveAfter) {
		id := state.Retiring[0].KeyID
		if err := r.removeGPG(ctx, api, key, []string{id}); err != nil {
			return err
		}
		state.Retiring = state.Retiring[1:]
		writeGPGState(&secret, state)
		if err := r.Update(ctx, &secret); err != nil {
			return err
		}
		key.Status.ManagedKeyIDs = slices.DeleteFunc(key.Status.ManagedKeyIDs, func(v string) bool { return v == id })
	}
	due := key.Spec.Rotation != nil && key.Spec.Rotation.After != nil && !r.now().Before(state.CreatedAt.Add(key.Spec.Rotation.After.Duration))
	if due && len(state.Retiring) == 0 && len(secret.Data[gpgPendingPrivate]) == 0 {
		pending, err := credentials.GenerateGPG(key.Spec.Identity.Name, key.Spec.Identity.Email, key.Spec.Algorithm, r.now())
		if err != nil {
			return err
		}
		secret.Data[gpgPendingPrivate] = pending.Private
		if err := r.Update(ctx, &secret); err != nil {
			return err
		}
	}
	if len(secret.Data[gpgPendingPrivate]) != 0 {
		pending, err := credentials.ReadGPG(secret.Data[gpgPendingPrivate], key.Spec.Identity.Name, key.Spec.Identity.Email, key.Spec.Algorithm)
		if err != nil {
			return err
		}
		if pending.KeyID == material.KeyID {
			return errors.New("staged key must differ from the current signing key")
		}
		remote, err := r.registerGPG(ctx, api, key, pending)
		if err != nil {
			return err
		}
		state.Retiring = append(state.Retiring, gpgRetiring{KeyID: material.KeyID, RemoveAfter: r.now().Add(gpgGracePeriod(key))})
		state.CreatedAt = r.now()
		writeGPGOutputs(&secret, outputs, pending)
		delete(secret.Data, gpgPendingPrivate)
		writeGPGState(&secret, state)
		if err := r.Update(ctx, &secret); err != nil {
			return err
		}
		key.Status.KeyID, key.Status.Fingerprint, key.Status.RemoteID = pending.KeyID, pending.Fingerprint, strconv.FormatInt(remote, 10)
	}
	// Successful promotion/retirement makes the Secret's transaction record the
	// complete set. This also repairs a status update lost after retirement.
	key.Status.ManagedKeyIDs = []string{key.Status.KeyID}
	for _, old := range state.Retiring {
		key.Status.ManagedKeyIDs = append(key.Status.ManagedKeyIDs, old.KeyID)
	}
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
	if !slices.Contains(key.Status.ManagedKeyIDs, material.KeyID) {
		key.Status.ManagedKeyIDs = append(key.Status.ManagedKeyIDs, material.KeyID)
		if err := r.Status().Update(ctx, key); err != nil {
			return 0, err
		}
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

func (r *GPGKeyReconciler) deleteGPGKeys(ctx context.Context, api *forgeapi.Client, key *forgev1.ForgejoGPGKey) error {
	return r.removeGPG(ctx, api, key, key.Status.ManagedKeyIDs)
}
