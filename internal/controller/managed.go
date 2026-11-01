package controller

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	"github.com/jakeschurch/forgejo-operator/internal/credentials"
	forgeapi "github.com/jakeschurch/forgejo-operator/internal/forgejo"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type managedReconciler struct {
	Reconciler
	newObject func() client.Object
	// deployKeys guards the delete-and-recreate path of immutable deploy keys
	// against an unbounded loop, and remembers a recreate that left a
	// repository keyless.
	deployKeysMu sync.Mutex
	deployKeys   map[string]deployKeyState
}

func (r *managedReconciler) SetupWithManager(m ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(m).For(r.newObject()).Complete(r)
}

func (r *managedReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	object := r.newObject()
	if err := r.Get(ctx, req.NamespacedName, object); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	spec, status := managedFields(object)
	if spec == nil {
		return ctrl.Result{}, errors.New("unsupported managed object")
	}
	api, err := r.providerClient(ctx, object.GetNamespace(), spec.ProviderRef)
	if err == nil {
		err = r.ensureUniqueOwner(ctx, object)
	}
	if err == nil && object.GetDeletionTimestamp().IsZero() {
		if spec.DeletionPolicy == forgev1.DeletionPolicyDelete && !contains(object.GetFinalizers(), finalizer) {
			object.SetFinalizers(append(object.GetFinalizers(), finalizer))
			if err = r.Update(ctx, object); err != nil {
				return ctrl.Result{}, err
			}
		}
		var id string
		id, err = r.reconcile(ctx, api, object)
		if err == nil && id != "" {
			status.RemoteID = id
			status.GeneratedSecrets = generatedSecretRefs(object)
		}
		var orphaned *deployKeyOrphanedError
		if errors.As(err, &orphaned) {
			// The remote key was deleted and not replaced: stop advertising an
			// id that no longer resolves.
			status.RemoteID = ""
		}
	} else if err == nil {
		if contains(object.GetFinalizers(), finalizer) {
			if spec.DeletionPolicy == forgev1.DeletionPolicyDelete {
				err = r.deleteRemote(ctx, api, object, status.RemoteID)
				if err == nil {
					for _, ref := range status.GeneratedSecrets {
						secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: ref.Name, Namespace: object.GetNamespace()}}
						if deleteErr := r.Delete(ctx, secret); deleteErr != nil && !apierrors.IsNotFound(deleteErr) {
							err = deleteErr
							break
						}
					}
				}
			}
			if err == nil {
				object.SetFinalizers(remove(object.GetFinalizers(), finalizer))
				return ctrl.Result{}, r.Update(ctx, object)
			}
		}
		if err == nil {
			return ctrl.Result{}, nil
		}
		// A failed remote delete keeps the finalizer: report it and retry, or the
		// object sits in Terminating with nothing saying why.
	}
	setStatus(status, object.GetGeneration(), err)
	if updateErr := r.Status().Update(ctx, object); updateErr != nil && !apierrors.IsNotFound(updateErr) {
		return ctrl.Result{}, updateErr
	}
	if err != nil {
		return ctrl.Result{RequeueAfter: time.Minute}, nil
	}
	return ctrl.Result{RequeueAfter: 10 * time.Minute}, nil
}

func managedFields(object client.Object) (*forgev1.CommonSpec, *forgev1.CommonStatus) {
	switch v := object.(type) {
	case *forgev1.ForgejoTeam:
		return &v.Spec.CommonSpec, &v.Status
	case *forgev1.ForgejoMembership:
		return &v.Spec.CommonSpec, &v.Status
	case *forgev1.ForgejoRobotAccount:
		return &v.Spec.CommonSpec, &v.Status
	case *forgev1.ForgejoAccessToken:
		return &v.Spec.CommonSpec, &v.Status
	case *forgev1.ForgejoCollaborator:
		return &v.Spec.CommonSpec, &v.Status
	case *forgev1.ForgejoDeployKey:
		return &v.Spec.CommonSpec, &v.Status
	case *forgev1.ForgejoWebhook:
		return &v.Spec.CommonSpec, &v.Status
	case *forgev1.ForgejoPushMirror:
		return &v.Spec.CommonSpec, &v.Status
	case *forgev1.ForgejoBranchProtection:
		return &v.Spec.CommonSpec, &v.Status
	case *forgev1.ForgejoTagProtection:
		return &v.Spec.CommonSpec, &v.Status
	case *forgev1.ForgejoLabel:
		return &v.Spec.CommonSpec, &v.Status
	default:
		return nil, nil
	}
}

func generatedSecretRefs(object client.Object) []corev1.LocalObjectReference {
	var name string
	switch v := object.(type) {
	case *forgev1.ForgejoRobotAccount:
		name = v.Spec.PasswordSecretName
		if name == "" {
			name = v.Name + "-password"
		}
	case *forgev1.ForgejoAccessToken:
		name = v.Spec.SecretName
		if name == "" {
			name = v.Name + "-token"
		}
	case *forgev1.ForgejoWebhook:
		if v.Spec.SecretRef == nil {
			name = v.Spec.GeneratedSecretName
			if name == "" {
				name = v.Name + "-secret"
			}
		}
	}
	if name == "" {
		return nil
	}
	return []corev1.LocalObjectReference{{Name: name}}
}

func (r *managedReconciler) secretValue(ctx context.Context, namespace string, ref corev1.SecretKeySelector, defaultKey string) (string, error) {
	var secret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: ref.Name}, &secret); err != nil {
		return "", fmt.Errorf("get referenced Secret: %w", err)
	}
	key := ref.Key
	if key == "" {
		key = defaultKey
	}
	value := secret.Data[key]
	if len(value) == 0 {
		return "", fmt.Errorf("referenced Secret key %q is empty", key)
	}
	return string(value), nil
}

func (r *managedReconciler) generatedSecret(ctx context.Context, object client.Object, name, key, nonce string) (*corev1.Secret, error) {
	var existing corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: object.GetNamespace(), Name: name}, &existing)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}
	var current *corev1.Secret
	if err == nil {
		current = &existing
	}
	owner := metav1.OwnerReference{
		APIVersion: forgev1.GroupVersion.String(), Kind: object.GetObjectKind().GroupVersionKind().Kind,
		Name: object.GetName(), UID: object.GetUID(),
	}
	secret, changed, err := credentials.StableSecret(current, object.GetNamespace(), name, key, nonce, owner)
	if err != nil {
		return nil, err
	}
	// Generated credentials outlive orphaned CRs. A finalizer explicitly deletes
	// them only after successful remote deletion.
	secret.OwnerReferences = nil
	if changed {
		if current == nil {
			err = r.Create(ctx, secret)
		} else {
			secret.ResourceVersion = current.ResourceVersion
			err = r.Update(ctx, secret)
		}
	}
	return secret, err
}

func (r *managedReconciler) reconcile(ctx context.Context, api *forgeapi.Client, object client.Object) (string, error) {
	switch v := object.(type) {
	case *forgev1.ForgejoTeam:
		var found struct {
			Data []struct {
				ID   int64  `json:"id"`
				Name string `json:"name"`
			} `json:"data"`
		}
		path := "orgs/" + esc(v.Spec.Organization) + "/teams/search?q=" + url.QueryEscape(v.Spec.Name)
		if err := api.Do(ctx, http.MethodGet, path, nil, &found); err != nil {
			return "", err
		}
		payload := map[string]any{"name": v.Spec.Name, "description": v.Spec.Description, "permission": v.Spec.Permission, "includes_all_repositories": v.Spec.IncludesAllRepositories, "units": v.Spec.Units}
		var id int64
		for _, team := range found.Data {
			if team.Name == v.Spec.Name {
				id = team.ID
				break
			}
		}
		if id == 0 {
			var created struct {
				ID int64 `json:"id"`
			}
			if err := api.Do(ctx, http.MethodPost, "orgs/"+esc(v.Spec.Organization)+"/teams", payload, &created); err != nil {
				return "", err
			}
			id = created.ID
		} else if err := api.Do(ctx, http.MethodPatch, "teams/"+strconv.FormatInt(id, 10), payload, nil); err != nil {
			return "", err
		}
		for _, repo := range v.Spec.Repositories {
			if err := api.Do(ctx, http.MethodPut, fmt.Sprintf("teams/%d/repos/%s/%s", id, esc(v.Spec.Organization), esc(repo)), nil, nil); err != nil {
				return "", err
			}
		}
		return strconv.FormatInt(id, 10), nil
	case *forgev1.ForgejoMembership:
		if len(v.Spec.Teams) == 0 {
			if err := api.Do(ctx, http.MethodGet, "orgs/"+esc(v.Spec.Organization)+"/members/"+esc(v.Spec.Username), nil, nil); err != nil {
				return "", fmt.Errorf("membership requires an existing organization membership or at least one team: %w", err)
			}
		}
		for _, teamName := range v.Spec.Teams {
			id, err := findTeam(ctx, api, v.Spec.Organization, teamName)
			if err != nil {
				return "", err
			}
			if err := api.Do(ctx, http.MethodPut, fmt.Sprintf("teams/%d/members/%s", id, esc(v.Spec.Username)), nil, nil); err != nil {
				return "", err
			}
		}
		return v.Spec.Organization + "/" + v.Spec.Username, nil
	case *forgev1.ForgejoRobotAccount:
		name := v.Spec.PasswordSecretName
		if name == "" {
			name = v.Name + "-password"
		}
		secret, err := r.generatedSecret(ctx, v, name, "password", v.Spec.RotationNonce)
		if err != nil {
			return "", err
		}
		var remote struct {
			ID int64 `json:"id"`
		}
		err = api.Do(ctx, http.MethodGet, "users/"+esc(v.Spec.Username), nil, &remote)
		if isNotFound(err) {
			err = api.Do(ctx, http.MethodPost, "admin/users", map[string]any{"username": v.Spec.Username, "email": v.Spec.Email, "password": string(secret.Data["password"]), "must_change_password": false, "admin": false}, &remote)
		}
		return strconv.FormatInt(remote.ID, 10), err
	case *forgev1.ForgejoAccessToken:
		if v.Spec.AccountType == forgev1.AccessTokenAccountHuman {
			return r.reconcileHumanAccessToken(ctx, api, v)
		}
		name := v.Spec.SecretName
		if name == "" {
			name = v.Name + "-token"
		}
		var existing corev1.Secret
		err := r.Get(ctx, types.NamespacedName{Namespace: v.Namespace, Name: name}, &existing)
		exists := err == nil
		if err == nil && existing.Annotations[credentials.RotationNonceAnnotation] == v.Spec.RotationNonce && len(existing.Data["token"]) > 0 {
			return v.Spec.Username + "/" + v.Spec.Name, nil
		}
		if err != nil && !apierrors.IsNotFound(err) {
			return "", err
		}
		password, err := r.robotPassword(ctx, v)
		if err != nil {
			return "", err
		}
		// Forgejo refuses a token name already in use on the account, so the
		// token being rotated has to go first.
		if nonce, managed := existing.Annotations[credentials.RotationNonceAnnotation]; exists && managed && nonce != v.Spec.RotationNonce {
			if err := revokeRobotToken(ctx, api, v, password); err != nil {
				return "", fmt.Errorf("revoke rotated token: %w", err)
			}
		}
		var created struct {
			ID   int64  `json:"id"`
			SHA1 string `json:"sha1"`
		}
		path := "users/" + esc(v.Spec.Username) + "/tokens"
		if err := api.DoBasic(ctx, http.MethodPost, path, v.Spec.Username, password, map[string]any{"name": v.Spec.Name, "scopes": v.Spec.Scopes}, &created); err != nil {
			return "", err
		}
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: v.Namespace, Annotations: map[string]string{credentials.RotationNonceAnnotation: v.Spec.RotationNonce}}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"token": []byte(created.SHA1)}}
		if exists {
			secret.ResourceVersion = existing.ResourceVersion
			err = r.Update(ctx, secret)
		} else {
			err = r.Create(ctx, secret)
		}
		id := strconv.FormatInt(created.ID, 10)
		if err != nil {
			// The value is unrecoverable, and an unstored token blocks its own name.
			if revokeErr := revokeAccessToken(ctx, api, v, v.Spec.Username, password, id); revokeErr != nil {
				return "", fmt.Errorf("store token: %w; revoke unstored token %s: %w", err, id, revokeErr)
			}
			return "", fmt.Errorf("store token: %w", err)
		}
		return id, nil
	case *forgev1.ForgejoCollaborator:
		path := repoPath(v.Spec.Owner, v.Spec.Repository) + "/collaborators/" + esc(v.Spec.Username)
		return v.Spec.Username, api.Do(ctx, http.MethodPut, path, map[string]any{"permission": v.Spec.Permission}, nil)
	case *forgev1.ForgejoDeployKey:
		return r.reconcileDeployKey(ctx, api, v)
	case *forgev1.ForgejoWebhook:
		secret := ""
		if v.Spec.SecretRef != nil {
			var err error
			secret, err = r.secretValue(ctx, v.Namespace, *v.Spec.SecretRef, "secret")
			if err != nil {
				return "", err
			}
		} else {
			name := v.Spec.GeneratedSecretName
			if name == "" {
				name = v.Name + "-secret"
			}
			generated, err := r.generatedSecret(ctx, v, name, "secret", v.Spec.RotationNonce)
			if err != nil {
				return "", err
			}
			secret = string(generated.Data["secret"])
		}
		path := hookBase(v.Spec.Owner, v.Spec.Repository)
		var hooks []struct {
			ID     int64             `json:"id"`
			Config map[string]string `json:"config"`
		}
		if err := api.Do(ctx, http.MethodGet, path, nil, &hooks); err != nil {
			return "", err
		}
		active := true
		if v.Spec.Active != nil {
			active = *v.Spec.Active
		}
		payload := map[string]any{
			"type":                 "forgejo",
			"active":               active,
			"events":               v.Spec.Events,
			"authorization_header": "Bearer " + secret,
			"config": map[string]string{
				"url":          v.Spec.URL,
				"content_type": "json",
				"secret":       secret,
			},
		}
		for _, hook := range hooks {
			if hook.Config["url"] == v.Spec.URL {
				return strconv.FormatInt(hook.ID, 10), api.Do(ctx, http.MethodPatch, path+"/"+strconv.FormatInt(hook.ID, 10), payload, nil)
			}
		}
		var created struct {
			ID int64 `json:"id"`
		}
		err := api.Do(ctx, http.MethodPost, path, payload, &created)
		return strconv.FormatInt(created.ID, 10), err
	case *forgev1.ForgejoPushMirror:
		credential, err := r.secretValue(ctx, v.Namespace, v.Spec.CredentialsSecretRef, "token")
		if err != nil {
			return "", err
		}
		path := repoPath(v.Spec.Owner, v.Spec.Repository) + "/push_mirrors"
		var mirrors []struct {
			ID            int64  `json:"id"`
			RemoteAddress string `json:"remote_address"`
		}
		if err := api.Do(ctx, http.MethodGet, path, nil, &mirrors); err != nil {
			return "", err
		}
		for _, mirror := range mirrors {
			if mirror.RemoteAddress == v.Spec.DestinationURL {
				// Adopt only. An existing mirror's credentials are never
				// rewritten, for three reasons. (1) The listing returns
				// remote_address with its credentials stripped -- that is why
				// matching on it works at all -- so the operator cannot observe
				// the stored username and cannot tell whether there is drift to
				// repair. (2) Forgejo has no PATCH for a mirror's remote, so any
				// correction is delete-and-recreate, and a freshly created push
				// mirror SYNCS: `git push --mirror` deletes every destination
				// ref the source lacks. That is exactly the 2026-09-22 incident
				// in which 162 refs were destroyed on GitHub. (3) Safe
				// sequencing -- reconcile the refs, then let it authenticate --
				// requires a human looking at both sides.
				return strconv.FormatInt(mirror.ID, 10), nil
			}
		}
		var created struct {
			ID int64 `json:"id"`
		}
		payload := map[string]any{"remote_address": v.Spec.DestinationURL, "remote_password": credential, "interval": v.Spec.Interval, "sync_on_commit": v.Spec.SyncOnCommit}
		// Only send remote_username when it is declared, so the request stays
		// byte-identical for every mirror that does not set it.
		if v.Spec.RemoteUsername != "" {
			payload["remote_username"] = v.Spec.RemoteUsername
		}
		err = api.Do(ctx, http.MethodPost, path, payload, &created)
		return strconv.FormatInt(created.ID, 10), err
	case *forgev1.ForgejoBranchProtection:
		path := repoPath(v.Spec.Owner, v.Spec.Repository) + "/branch_protections/" + esc(v.Spec.Branch)
		payload := map[string]any{"branch_name": v.Spec.Branch, "required_approvals": v.Spec.RequiredApprovals, "status_check_contexts": v.Spec.RequiredStatusContexts, "enable_push": v.Spec.EnablePush, "enable_merge_whitelist": v.Spec.EnableMerge}
		var remote map[string]any
		err := api.Do(ctx, http.MethodGet, path, nil, &remote)
		if isNotFound(err) {
			err = api.Do(ctx, http.MethodPost, repoPath(v.Spec.Owner, v.Spec.Repository)+"/branch_protections", payload, &remote)
		} else if err == nil {
			err = api.Do(ctx, http.MethodPatch, path, payload, nil)
		}
		return v.Spec.Branch, err
	case *forgev1.ForgejoTagProtection:
		path := repoPath(v.Spec.Owner, v.Spec.Repository) + "/tag_protections"
		var protections []struct {
			ID          int64  `json:"id"`
			NamePattern string `json:"name_pattern"`
		}
		if err := api.Do(ctx, http.MethodGet, path, nil, &protections); err != nil {
			return "", err
		}
		payload := map[string]any{"name_pattern": v.Spec.Pattern, "whitelist_users": v.Spec.WhitelistUsers, "whitelist_teams": v.Spec.WhitelistTeams}
		for _, p := range protections {
			if p.NamePattern == v.Spec.Pattern {
				return strconv.FormatInt(p.ID, 10), api.Do(ctx, http.MethodPatch, path+"/"+strconv.FormatInt(p.ID, 10), payload, nil)
			}
		}
		var created struct {
			ID int64 `json:"id"`
		}
		err := api.Do(ctx, http.MethodPost, path, payload, &created)
		return strconv.FormatInt(created.ID, 10), err
	case *forgev1.ForgejoLabel:
		path := labelBase(v.Spec.Owner, v.Spec.Repository)
		var labels []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		}
		if err := api.Do(ctx, http.MethodGet, path+"?limit=100", nil, &labels); err != nil {
			return "", err
		}
		payload := map[string]any{"name": v.Spec.Name, "color": v.Spec.Color, "description": v.Spec.Description}
		for _, label := range labels {
			if label.Name == v.Spec.Name {
				return strconv.FormatInt(label.ID, 10), api.Do(ctx, http.MethodPatch, path+"/"+strconv.FormatInt(label.ID, 10), payload, nil)
			}
		}
		var created struct {
			ID int64 `json:"id"`
		}
		err := api.Do(ctx, http.MethodPost, path, payload, &created)
		return strconv.FormatInt(created.ID, 10), err
	default:
		return "", errors.New("unsupported managed resource")
	}
}

func (r *managedReconciler) deleteRemote(ctx context.Context, api *forgeapi.Client, object client.Object, id string) error {
	// Without a recorded id there is nothing to address: never aim a DELETE at
	// a collection endpoint on a guess.
	if id == "" {
		return nil
	}
	if token, ok := object.(*forgev1.ForgejoAccessToken); ok {
		if token.Spec.AccountType == forgev1.AccessTokenAccountHuman {
			return r.deleteHumanAccessToken(ctx, api, token, id)
		}
		return r.deleteRobotAccessToken(ctx, api, token)
	}
	var path string
	switch v := object.(type) {
	case *forgev1.ForgejoTeam:
		path = "teams/" + id
	case *forgev1.ForgejoMembership:
		path = "orgs/" + esc(v.Spec.Organization) + "/members/" + esc(v.Spec.Username)
	case *forgev1.ForgejoRobotAccount:
		path = "admin/users/" + esc(v.Spec.Username)
	case *forgev1.ForgejoCollaborator:
		path = repoPath(v.Spec.Owner, v.Spec.Repository) + "/collaborators/" + esc(v.Spec.Username)
	case *forgev1.ForgejoDeployKey:
		path = repoPath(v.Spec.Owner, v.Spec.Repository) + "/keys/" + id
	case *forgev1.ForgejoWebhook:
		path = hookBase(v.Spec.Owner, v.Spec.Repository) + "/" + id
	case *forgev1.ForgejoPushMirror:
		path = repoPath(v.Spec.Owner, v.Spec.Repository) + "/push_mirrors/" + id
	case *forgev1.ForgejoBranchProtection:
		path = repoPath(v.Spec.Owner, v.Spec.Repository) + "/branch_protections/" + esc(v.Spec.Branch)
	case *forgev1.ForgejoTagProtection:
		path = repoPath(v.Spec.Owner, v.Spec.Repository) + "/tag_protections/" + id
	case *forgev1.ForgejoLabel:
		path = labelBase(v.Spec.Owner, v.Spec.Repository) + "/" + id
	}
	if path == "" {
		return nil
	}
	err := api.Do(ctx, http.MethodDelete, path, nil, nil)
	if isNotFound(err) {
		return nil
	}
	return err
}

// maxDeployKeyRecreates bounds how many times one generation of a deploy key
// may delete and recreate its live credential before the operator gives up. A
// server that does not return the declared title verbatim would otherwise
// recreate a working credential on every single reconcile, forever.
const maxDeployKeyRecreates = 3

const (
	// deployKeyCreateAttempts bounds the in-reconcile retry of the POST that
	// follows a successful DELETE: until it lands the repository has no key.
	deployKeyCreateAttempts = 3
	deployKeyRetryBackoff   = 150 * time.Millisecond
	deployKeyPageSize       = 50
	// maxDeployKeyPages bounds the listing walk so a server that keeps
	// returning full pages cannot spin the reconcile forever.
	maxDeployKeyPages = 100
)

// errDeployKeyCreatedWithoutID reports a create that Forgejo accepted without
// returning a usable id. The key may well exist, so this is never retried: a
// second POST of the same material is rejected as a duplicate.
var errDeployKeyCreatedWithoutID = errors.New("Forgejo accepted the deploy key without returning an id")

// deployKeyOrphanedError reports the one state this controller cannot repair on
// its own: the remote key was deleted and the replacement was refused, so the
// repository currently has no deploy key at all.
type deployKeyOrphanedError struct{ err error }

func (e *deployKeyOrphanedError) Error() string {
	return "remote deploy key was deleted and not recreated, the repository has no deploy key: " + e.err.Error()
}
func (e *deployKeyOrphanedError) Unwrap() error           { return e.err }
func (e *deployKeyOrphanedError) ConditionReason() string { return "RemoteKeyDeletedNotRecreated" }

// remoteDeployKey is the authoritative Forgejo representation of a deploy key.
// Only GET .../keys/{id} is trusted for read_only and title; the repository
// listing is used solely to locate an id.
type remoteDeployKey struct {
	ID       int64  `json:"id"`
	Title    string `json:"title"`
	Key      string `json:"key"`
	ReadOnly bool   `json:"read_only"`
}

// deployKeyState tracks, per object generation, how often the live credential
// has been deleted and recreated and whether a recreate left it orphaned. It is
// process-local on purpose: it guards against an unbounded loop, which is a
// within-process concern, and keeps the CRD surface unchanged.
type deployKeyState struct {
	generation int64
	recreates  int
	orphaned   bool
}

func deployKeyStateKey(v *forgev1.ForgejoDeployKey) string {
	if v.UID != "" {
		return string(v.UID)
	}
	return v.Namespace + "/" + v.Name
}

func (r *managedReconciler) deployKeyState(v *forgev1.ForgejoDeployKey) deployKeyState {
	entry := r.deployKeys[deployKeyStateKey(v)]
	if entry.generation != v.Generation {
		return deployKeyState{generation: v.Generation}
	}
	return entry
}

func (r *managedReconciler) putDeployKeyState(v *forgev1.ForgejoDeployKey, entry deployKeyState) {
	if r.deployKeys == nil {
		r.deployKeys = map[string]deployKeyState{}
	}
	r.deployKeys[deployKeyStateKey(v)] = entry
}

func deployKeyBudgetExhausted(entry deployKeyState) error {
	return fmt.Errorf("deploy key was recreated %d times for generation %d without converging; refusing to delete the live key again", entry.recreates, entry.generation)
}

// checkDeployKeyRecreateBudget refuses a delete-and-recreate whose budget this
// generation has already burned. It is consulted before the DELETE, so an
// exhausted budget leaves the live credential untouched rather than deleting a
// key it has already decided not to replace.
func (r *managedReconciler) checkDeployKeyRecreateBudget(v *forgev1.ForgejoDeployKey) error {
	r.deployKeysMu.Lock()
	defer r.deployKeysMu.Unlock()
	entry := r.deployKeyState(v)
	r.putDeployKeyState(v, entry)
	if entry.recreates >= maxDeployKeyRecreates {
		return deployKeyBudgetExhausted(entry)
	}
	return nil
}

// chargeDeployKeyRecreate accounts for one delete-and-recreate of the live
// credential, refusing once this generation has burned its budget. It is only
// called once the DELETE has actually landed: the loop this budget bounds always
// deletes, so charging a DELETE that failed would let a transient 5xx or a
// momentary 403 permanently wedge a resource whose live key is still intact.
func (r *managedReconciler) chargeDeployKeyRecreate(v *forgev1.ForgejoDeployKey) error {
	r.deployKeysMu.Lock()
	defer r.deployKeysMu.Unlock()
	entry := r.deployKeyState(v)
	if entry.recreates >= maxDeployKeyRecreates {
		r.putDeployKeyState(v, entry)
		return deployKeyBudgetExhausted(entry)
	}
	entry.recreates++
	r.putDeployKeyState(v, entry)
	return nil
}

func (r *managedReconciler) markDeployKeyOrphaned(v *forgev1.ForgejoDeployKey, orphaned bool) {
	r.deployKeysMu.Lock()
	defer r.deployKeysMu.Unlock()
	entry := r.deployKeyState(v)
	entry.orphaned = orphaned
	r.putDeployKeyState(v, entry)
}

func (r *managedReconciler) deployKeyOrphaned(v *forgev1.ForgejoDeployKey) bool {
	r.deployKeysMu.Lock()
	defer r.deployKeysMu.Unlock()
	return r.deployKeyState(v).orphaned
}

func (r *managedReconciler) forgetDeployKey(v *forgev1.ForgejoDeployKey) {
	r.deployKeysMu.Lock()
	defer r.deployKeysMu.Unlock()
	delete(r.deployKeys, deployKeyStateKey(v))
}

// reconcileDeployKey converges a deploy key. Forgejo deploy keys are immutable:
// the API offers POST, GET and DELETE but no PATCH for read_only or title, so a
// divergent key is deleted and recreated instead of being declared in sync.
// Create-before-delete is impossible — Forgejo rejects duplicate key content in
// a repository whatever the title — so the delete comes first and the recovery
// lives in the error handling: the create is retried while it can still land,
// and a terminal failure is reported as an explicit keyless outage. The remote
// key is only ever deleted once its public key matches the one this resource
// declares.
func (r *managedReconciler) reconcileDeployKey(ctx context.Context, api *forgeapi.Client, v *forgev1.ForgejoDeployKey) (string, error) {
	key, err := r.secretValue(ctx, v.Namespace, v.Spec.PublicKeySecretRef, "publicKey")
	if err != nil {
		return "", err
	}
	want := deployKeyIdentity(key)
	if want == "" {
		return "", errors.New("declared deploy key is empty")
	}
	title := normalizeDeployKeyTitle(v.Spec.Title)
	base := repoPath(v.Spec.Owner, v.Spec.Repository) + "/keys"

	var remote remoteDeployKey
	found := false
	// The recorded id is authoritative when it still resolves. A stale id (the
	// key was deleted or replaced out of band) falls through to the listing.
	if v.Status.RemoteID != "" {
		if recorded, parseErr := strconv.ParseInt(v.Status.RemoteID, 10, 64); parseErr == nil && recorded > 0 {
			err := api.Do(ctx, http.MethodGet, base+"/"+strconv.FormatInt(recorded, 10), nil, &remote)
			switch {
			case err == nil:
				found = true
			case isNotFound(err):
			default:
				return "", err
			}
		}
	}
	if !found {
		id, findErr := findDeployKey(ctx, api, base, title, want)
		if findErr != nil {
			return "", findErr
		}
		if id != 0 {
			err := api.Do(ctx, http.MethodGet, base+"/"+strconv.FormatInt(id, 10), nil, &remote)
			switch {
			case err == nil:
				found = true
			case isNotFound(err):
			default:
				return "", err
			}
		}
	}
	if !found {
		id, createErr := createDeployKey(ctx, api, base, v, key)
		if createErr != nil {
			// A key this resource used to own is gone and cannot be replaced:
			// keep reporting the keyless window until a create succeeds.
			if r.deployKeyOrphaned(v) || v.Status.RemoteID != "" {
				r.markDeployKeyOrphaned(v, true)
				return "", &deployKeyOrphanedError{err: createErr}
			}
			return "", createErr
		}
		r.markDeployKeyOrphaned(v, false)
		return id, nil
	}
	if deployKeyIdentity(remote.Key) != want {
		return "", errors.New("adopted deploy key differs; rotate with a new title")
	}
	if normalizeDeployKeyTitle(remote.Title) == title && remote.ReadOnly == v.Spec.ReadOnly {
		r.forgetDeployKey(v)
		return strconv.FormatInt(remote.ID, 10), nil
	}
	if err := r.checkDeployKeyRecreateBudget(v); err != nil {
		return "", err
	}
	path := base + "/" + strconv.FormatInt(remote.ID, 10)
	if err := api.Do(ctx, http.MethodDelete, path, nil, nil); err != nil && !isNotFound(err) {
		// Nothing was deleted, so nothing is charged: the live key still works
		// and the next reconcile gets its full budget back.
		return "", err
	}
	if err := r.chargeDeployKeyRecreate(v); err != nil {
		return "", err
	}
	return r.recreateDeployKey(ctx, api, base, v, key)
}

// recreateDeployKey runs the POST that follows a successful DELETE. Until it
// succeeds the repository has no deploy key, so a failure that could still land
// is retried here instead of waiting for the next requeue; a failure that never
// will (Forgejo already holds this key as a user SSH key, say) is reported as an
// explicit orphan so the keyless window is visible rather than silent.
func (r *managedReconciler) recreateDeployKey(ctx context.Context, api *forgeapi.Client, base string, v *forgev1.ForgejoDeployKey, key string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < deployKeyCreateAttempts; attempt++ {
		if attempt > 0 {
			if err := sleep(ctx, time.Duration(attempt)*deployKeyRetryBackoff); err != nil {
				lastErr = err
				break
			}
		}
		id, err := createDeployKey(ctx, api, base, v, key)
		if err == nil {
			r.markDeployKeyOrphaned(v, false)
			return id, nil
		}
		lastErr = err
		if !retryableCreateError(err) {
			break
		}
	}
	// A create whose response was lost still committed server-side, and every
	// later POST of the same material is refused as a duplicate. Confirm the
	// repository really has no key before raising the keyless alarm.
	if id, findErr := findDeployKey(ctx, api, base, normalizeDeployKeyTitle(v.Spec.Title), deployKeyIdentity(key)); findErr == nil && id != 0 {
		r.markDeployKeyOrphaned(v, false)
		return strconv.FormatInt(id, 10), nil
	}
	r.markDeployKeyOrphaned(v, true)
	return "", &deployKeyOrphanedError{err: lastErr}
}

// retryableCreateError reports whether a create could still succeed on a retry.
// Every 4xx other than 429 is Forgejo's final answer, and a create that returned
// no id may already have taken effect, so neither is retried.
func retryableCreateError(err error) bool {
	if errors.Is(err, errDeployKeyCreatedWithoutID) {
		return false
	}
	var apiErr *forgeapi.APIError
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode == http.StatusTooManyRequests || apiErr.StatusCode >= 500
	}
	return true
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// findDeployKey walks the repository key listing, which is paginated and whose
// page size the server may clamp below the requested limit. A title match wins
// over a fingerprint match, so the whole listing is scanned before falling back.
func findDeployKey(ctx context.Context, api *forgeapi.Client, base, title, want string) (int64, error) {
	var byIdentity int64
	pageSize, lastFirstID := 0, int64(0)
	for page := 1; page <= maxDeployKeyPages; page++ {
		var keys []remoteDeployKey
		path := base + "?limit=" + strconv.Itoa(deployKeyPageSize) + "&page=" + strconv.Itoa(page)
		if err := api.Do(ctx, http.MethodGet, path, nil, &keys); err != nil {
			return 0, err
		}
		if len(keys) == 0 {
			break
		}
		// A server that ignores the page parameter repeats the first page
		// forever; stop rather than walking the page cap every reconcile.
		if keys[0].ID == lastFirstID {
			break
		}
		lastFirstID = keys[0].ID
		for _, candidate := range keys {
			if normalizeDeployKeyTitle(candidate.Title) == title {
				return candidate.ID, nil
			}
			// Adopt by key material so a key recreated by hand, or one whose
			// title changed, is reclaimed instead of duplicated.
			if byIdentity == 0 && deployKeyIdentity(candidate.Key) == want {
				byIdentity = candidate.ID
			}
		}
		if pageSize == 0 {
			pageSize = len(keys)
		}
		if len(keys) < pageSize {
			break
		}
	}
	return byIdentity, nil
}

func createDeployKey(ctx context.Context, api *forgeapi.Client, base string, v *forgev1.ForgejoDeployKey, key string) (string, error) {
	var created struct {
		ID int64 `json:"id"`
	}
	payload := map[string]any{"title": normalizeDeployKeyTitle(v.Spec.Title), "key": key, "read_only": v.Spec.ReadOnly}
	if err := api.Do(ctx, http.MethodPost, base, payload, &created); err != nil {
		return "", err
	}
	if created.ID <= 0 {
		return "", errDeployKeyCreatedWithoutID
	}
	return strconv.FormatInt(created.ID, 10), nil
}

// normalizeDeployKeyTitle is applied to both the declared and the round-tripped
// title before they are compared, so surrounding whitespace the server trims is
// not mistaken for divergence and does not recreate a live credential.
func normalizeDeployKeyTitle(title string) string { return strings.TrimSpace(title) }

// deployKeyIdentity identifies a public key for comparison. Keys in OpenSSH
// one-line form are identified by their SHA-256 fingerprint; shapes the wire
// format parser cannot read (PEM, PKCS#8, RFC4716) fall back to the
// whitespace-normalised material, which is what this controller compared before
// fingerprinting existed. Such a key can still be created; it simply never
// matches a differently encoded remote key, and a mismatch never deletes.
func deployKeyIdentity(key string) string {
	if fingerprint := sshFingerprint(key); fingerprint != "" {
		return "sha256:" + fingerprint
	}
	if normalized := strings.Join(strings.Fields(key), " "); normalized != "" {
		return "raw:" + normalized
	}
	return ""
}

// sshFingerprint returns the SHA-256 fingerprint of an SSH public key's wire
// format, ignoring any trailing comment. It returns "" when the key cannot be
// parsed; callers must treat that as "never touch the remote key". The key
// material itself is never returned or logged.
func sshFingerprint(key string) string {
	fields := strings.Fields(strings.TrimSpace(key))
	if len(fields) < 2 {
		return ""
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(blob) == 0 {
		return ""
	}
	sum := sha256.Sum256(blob)
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

func findTeam(ctx context.Context, api *forgeapi.Client, org, name string) (int64, error) {
	var found struct {
		Data []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := api.Do(ctx, http.MethodGet, "orgs/"+esc(org)+"/teams/search?q="+url.QueryEscape(name), nil, &found); err != nil {
		return 0, err
	}
	for _, t := range found.Data {
		if t.Name == name {
			return t.ID, nil
		}
	}
	return 0, fmt.Errorf("team %q not found", name)
}
func isNotFound(err error) bool {
	var apiErr *forgeapi.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusNotFound
}
func esc(v string) string                { return url.PathEscape(v) }
func repoPath(owner, repo string) string { return "repos/" + esc(owner) + "/" + esc(repo) }
func hookBase(owner, repo string) string {
	if repo == "" {
		return "orgs/" + esc(owner) + "/hooks"
	}
	return repoPath(owner, repo) + "/hooks"
}
func labelBase(owner, repo string) string {
	if repo == "" {
		return "orgs/" + esc(owner) + "/labels"
	}
	return repoPath(owner, repo) + "/labels"
}
func contains(in []string, want string) bool {
	for _, v := range in {
		if v == want {
			return true
		}
	}
	return false
}
func remove(in []string, want string) []string {
	out := in[:0]
	for _, v := range in {
		if v != want {
			out = append(out, v)
		}
	}
	return out
}

var _ = json.Marshal
