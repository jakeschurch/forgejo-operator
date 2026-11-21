package controller

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	forgeapi "github.com/jakeschurch/forgejo-operator/internal/forgejo"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// sshUnverifiedRequeue polls Forgejo while the owner's one-time proof is
// outstanding, so status turns Verified within minutes of it.
const sshUnverifiedRequeue = 2 * time.Minute

// SSHKeyReconciler registers a user's existing SSH public key. Forgejo 17 marks
// SSH-signed commits Verified only for a key on the committer's account with
// verified=true. Verification is proof of possession: the owner signs a token
// that rotates every minute, and Forgejo accepts it only through the web
// settings form (there is no API route). The operator holds neither the private
// key nor a web session as the user, so it registers the key, never recreates
// it (a new key is unverified), and reports where the owner completes the proof.
type SSHKeyReconciler struct{ Reconciler }

var errSSHUnauthorized = errors.New("SSH key management is not authorized")

// sshKeyConflictError reports a fingerprint Forgejo already has elsewhere:
// another account's key or a deploy key. Fingerprints are instance-unique.
type sshKeyConflictError struct{ fingerprint string }

func (e *sshKeyConflictError) Error() string {
	return fmt.Sprintf("Forgejo refused key %s: it is already registered to another account or as a deploy key", e.fingerprint)
}
func (e *sshKeyConflictError) ConditionReason() string { return "KeyInUse" }

type sshUnauthorizedError struct{ err error }

func (e *sshUnauthorizedError) Error() string           { return e.err.Error() }
func (e *sshUnauthorizedError) Unwrap() error           { return e.err }
func (e *sshUnauthorizedError) ConditionReason() string { return "Unauthorized" }

type remoteSSHKey struct {
	ID          int64  `json:"id"`
	Fingerprint string `json:"fingerprint"`
	// Verified is absent before Forgejo 17, which does not report it.
	Verified *bool `json:"verified"`
	// Owner is present for site-administrator callers.
	Owner *struct {
		Login string `json:"login"`
	} `json:"user,omitempty"`
}

func (r *SSHKeyReconciler) SetupWithManager(m ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(m).
		For(&forgev1.ForgejoSSHKey{}, builder.WithPredicates(primaryResourceChanges())).
		Complete(r)
}

func sshProviderNS(key *forgev1.ForgejoSSHKey) string {
	return providerNS(key.Namespace, forgev1.CommonSpec{ProviderNamespace: key.Spec.ProviderNamespace})
}

func (r *SSHKeyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var key forgev1.ForgejoSSHKey
	if err := r.Get(ctx, req.NamespacedName, &key); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	fingerprint, err := userKeyFingerprint(key.Spec.PublicKey)
	if !key.DeletionTimestamp.IsZero() {
		if !contains(key.Finalizers, finalizer) {
			return ctrl.Result{}, nil
		}
		err = nil
		if key.Spec.DeletionPolicy == forgev1.DeletionPolicyDelete && key.Status.RemoteID != "" {
			err = r.deleteSSHKey(ctx, &key)
		}
		if err == nil {
			key.Finalizers = remove(key.Finalizers, finalizer)
			return ctrl.Result{}, r.Update(ctx, &key)
		}
		// A failed remote delete keeps the finalizer: report it and retry.
		return r.writeSSHStatus(ctx, &key, err)
	}
	if err == nil && key.Spec.DeletionPolicy == forgev1.DeletionPolicyDelete && !contains(key.Finalizers, finalizer) {
		key.Finalizers = append(key.Finalizers, finalizer)
		if err := r.Update(ctx, &key); err != nil {
			return ctrl.Result{}, err
		}
	}
	if err == nil {
		err = r.ensureUniqueOwner(ctx, &key)
	}
	if err == nil {
		err = r.reconcileSSHKey(ctx, &key, fingerprint)
	}
	return r.writeSSHStatus(ctx, &key, err)
}

func (r *SSHKeyReconciler) writeSSHStatus(ctx context.Context, key *forgev1.ForgejoSSHKey, reconcileErr error) (ctrl.Result, error) {
	setStatus(&key.Status.CommonStatus, key.Generation, reconcileErr)
	// Derived here, not earlier: a finalizer Update replaces the in-memory object.
	key.Status.Fingerprint, _ = userKeyFingerprint(key.Spec.PublicKey)
	verified := metav1.Condition{Type: "Verified", ObservedGeneration: key.Generation}
	switch {
	case key.Status.RemoteID == "":
		verified.Status, verified.Reason = metav1.ConditionUnknown, "NotRegistered"
		verified.Message = "the key is not registered yet"
	case key.Status.Verified == nil:
		verified.Status, verified.Reason = metav1.ConditionUnknown, "VerificationNotReported"
		verified.Message = "this Forgejo does not report key verification (added in Forgejo 17); check " + key.Status.VerificationURL
	case *key.Status.Verified:
		verified.Status, verified.Reason = metav1.ConditionTrue, "OwnershipProven"
		verified.Message = "Forgejo trusts signatures made with this key"
	default:
		verified.Status, verified.Reason = metav1.ConditionFalse, "OwnershipProofRequired"
		verified.Message = "Forgejo does not trust signatures from this key until " + key.Spec.User +
			" proves possession once: open " + key.Status.VerificationURL +
			", sign the shown token with ssh-keygen -Y sign, and submit the signature"
	}
	meta.SetStatusCondition(&key.Status.Conditions, verified)
	if err := r.Status().Update(ctx, key); err != nil && !apierrors.IsNotFound(err) {
		return ctrl.Result{}, err
	}
	switch {
	case reconcileErr != nil:
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	case key.Status.Verified != nil && !*key.Status.Verified:
		return ctrl.Result{RequeueAfter: sshUnverifiedRequeue}, nil
	default:
		return ctrl.Result{RequeueAfter: 10 * time.Minute}, nil
	}
}

// authorizedSSHClient applies the provider's sshKeys policy and refuses site
// administrator targets: Sudo as an administrator would be a privilege grant.
func (r *SSHKeyReconciler) authorizedSSHClient(ctx context.Context, key *forgev1.ForgejoSSHKey) (*forgeapi.Client, *forgev1.ForgejoProvider, error) {
	var provider forgev1.ForgejoProvider
	if err := r.Get(ctx, client.ObjectKey{Namespace: sshProviderNS(key), Name: key.Spec.ProviderRef}, &provider); err != nil {
		return nil, nil, fmt.Errorf("get provider: %w", err)
	}
	policy := provider.Spec.SSHKeys
	if policy == nil || !slices.Contains(policy.AllowedUsers, key.Spec.User) {
		return nil, nil, &sshUnauthorizedError{fmt.Errorf("%w: provider sshKeys.allowedUsers does not authorize the target user", errSSHUnauthorized)}
	}
	if key.Namespace != provider.Namespace && !slices.Contains(policy.AllowedNamespaces, key.Namespace) {
		return nil, nil, &sshUnauthorizedError{fmt.Errorf("%w: provider sshKeys.allowedNamespaces does not authorize this namespace", errSSHUnauthorized)}
	}
	api, err := r.providerClient(ctx, provider.Namespace, provider.Name)
	if err != nil {
		return nil, nil, err
	}
	admin, err := isSiteAdmin(ctx, api, key.Spec.User)
	if err != nil {
		return nil, nil, err
	}
	if admin {
		return nil, nil, &sshUnauthorizedError{fmt.Errorf("%w: site administrator target", errSSHUnauthorized)}
	}
	return api, &provider, nil
}

func (r *SSHKeyReconciler) reconcileSSHKey(ctx context.Context, key *forgev1.ForgejoSSHKey, fingerprint string) error {
	api, provider, err := r.authorizedSSHClient(ctx, key)
	if err != nil {
		return err
	}
	base := provider.Spec.ExternalURL
	if base == "" {
		base = provider.Spec.URL
	}
	key.Status.VerificationURL = strings.TrimRight(base, "/") + "/user/settings/keys?verify_ssh=" + url.QueryEscape(fingerprint)
	remote, err := findSSHKey(ctx, api, key.Spec.User, fingerprint)
	if err != nil {
		return err
	}
	if remote == nil {
		// Adopt-or-create by fingerprint, never by title: the title is not the
		// key, and a recreated key loses the owner's verification.
		var created remoteSSHKey
		err := api.DoSudo(ctx, http.MethodPost, "user/keys", key.Spec.User, map[string]any{"title": key.Spec.Title, "key": strings.TrimSpace(key.Spec.PublicKey)}, &created)
		var apiErr *forgeapi.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnprocessableEntity {
			// 422 is also a duplicate title; re-read so a title clash on our own
			// key is not misreported.
			if again, findErr := findSSHKey(ctx, api, key.Spec.User, fingerprint); findErr == nil && again != nil {
				remote = again
			} else {
				return &sshKeyConflictError{fingerprint: fingerprint}
			}
		} else if err != nil {
			return fmt.Errorf("register SSH key: %w", err)
		} else {
			if created.ID == 0 {
				return errors.New("Forgejo accepted the SSH key without returning an id")
			}
			remote = &created
		}
	}
	key.Status.RemoteID = strconv.FormatInt(remote.ID, 10)
	key.Status.Verified = remote.Verified
	return nil
}

// findSSHKey returns the user's key with this fingerprint. It must use
// users/{user}/keys: Forgejo's /user/keys?fingerprint= ignores the owner and
// would match another account's key.
func findSSHKey(ctx context.Context, api *forgeapi.Client, user, fingerprint string) (*remoteSSHKey, error) {
	var keys []remoteSSHKey
	if err := api.Do(ctx, http.MethodGet, "users/"+url.PathEscape(user)+"/keys?fingerprint="+url.QueryEscape(fingerprint), nil, &keys); err != nil {
		return nil, fmt.Errorf("list SSH keys: %w", err)
	}
	for i := range keys {
		owner := keys[i].Owner
		if keys[i].Fingerprint == fingerprint && (owner == nil || owner.Login == user) {
			return &keys[i], nil
		}
	}
	return nil, nil
}

func (r *SSHKeyReconciler) deleteSSHKey(ctx context.Context, key *forgev1.ForgejoSSHKey) error {
	api, _, err := r.authorizedSSHClient(ctx, key)
	if err != nil {
		return err
	}
	fingerprint, err := userKeyFingerprint(key.Spec.PublicKey)
	if err != nil {
		return nil
	}
	// Delete only the recorded key, and only while it still is the user's
	// key with the declared fingerprint.
	remote, err := findSSHKey(ctx, api, key.Spec.User, fingerprint)
	if err != nil || remote == nil || strconv.FormatInt(remote.ID, 10) != key.Status.RemoteID {
		return err
	}
	err = api.DoSudo(ctx, http.MethodDelete, "user/keys/"+key.Status.RemoteID, key.Spec.User, nil, nil)
	if isNotFound(err) {
		return nil
	}
	return err
}

// isSiteAdmin reports whether a Forgejo login is a site administrator.
func isSiteAdmin(ctx context.Context, api *forgeapi.Client, login string) (bool, error) {
	var user struct {
		IsAdmin *bool `json:"is_admin"`
	}
	if err := api.Do(ctx, http.MethodGet, "users/"+url.PathEscape(login), nil, &user); err != nil {
		return false, err
	}
	if user.IsAdmin == nil {
		return false, errors.New("unknown administrator status")
	}
	return *user.IsAdmin, nil
}

// userKeyFingerprint validates an authorized_keys line and returns its OpenSSH
// "SHA256:..." fingerprint, the form Forgejo stores and matches signatures against.
func userKeyFingerprint(line string) (string, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", errors.New("publicKey must be an authorized_keys line: <type> <base64> [comment]")
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", errors.New("publicKey: key data is not base64")
	}
	// The blob starts with its own length-prefixed type, which must agree.
	if len(blob) < 4 {
		return "", errors.New("publicKey: key data is truncated")
	}
	n := binary.BigEndian.Uint32(blob)
	if uint64(len(blob)) < 4+uint64(n) || !bytes.Equal(blob[4:4+n], []byte(fields[0])) {
		return "", errors.New("publicKey: key type does not match key data")
	}
	return "SHA256:" + sshFingerprint(line), nil
}
