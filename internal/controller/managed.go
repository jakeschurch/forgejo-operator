package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
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
		return ctrl.Result{}, nil
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
		var created struct {
			ID   int64  `json:"id"`
			SHA1 string `json:"sha1"`
		}
		path := "users/" + esc(v.Spec.Username) + "/tokens?sudo=" + url.QueryEscape(v.Spec.Username)
		if err := api.Do(ctx, http.MethodPost, path, map[string]any{"name": v.Spec.Name, "scopes": v.Spec.Scopes}, &created); err != nil {
			return "", err
		}
		secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: v.Namespace, Annotations: map[string]string{credentials.RotationNonceAnnotation: v.Spec.RotationNonce}}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"token": []byte(created.SHA1)}}
		if exists {
			secret.ResourceVersion = existing.ResourceVersion
			err = r.Update(ctx, secret)
		} else {
			err = r.Create(ctx, secret)
		}
		return strconv.FormatInt(created.ID, 10), err
	case *forgev1.ForgejoCollaborator:
		path := repoPath(v.Spec.Owner, v.Spec.Repository) + "/collaborators/" + esc(v.Spec.Username)
		return v.Spec.Username, api.Do(ctx, http.MethodPut, path, map[string]any{"permission": v.Spec.Permission}, nil)
	case *forgev1.ForgejoDeployKey:
		key, err := r.secretValue(ctx, v.Namespace, v.Spec.PublicKeySecretRef, "publicKey")
		if err != nil {
			return "", err
		}
		path := repoPath(v.Spec.Owner, v.Spec.Repository) + "/keys"
		var keys []struct {
			ID    int64  `json:"id"`
			Title string `json:"title"`
			Key   string `json:"key"`
		}
		if err := api.Do(ctx, http.MethodGet, path, nil, &keys); err != nil {
			return "", err
		}
		for _, remote := range keys {
			if remote.Title == v.Spec.Title {
				if strings.TrimSpace(remote.Key) != strings.TrimSpace(key) {
					return "", errors.New("adopted deploy key differs; rotate with a new title")
				}
				return strconv.FormatInt(remote.ID, 10), nil
			}
		}
		var created struct {
			ID int64 `json:"id"`
		}
		err = api.Do(ctx, http.MethodPost, path, map[string]any{"title": v.Spec.Title, "key": key, "read_only": v.Spec.ReadOnly}, &created)
		return strconv.FormatInt(created.ID, 10), err
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
		payload := map[string]any{"type": "forgejo", "active": active, "events": v.Spec.Events, "config": map[string]string{"url": v.Spec.URL, "content_type": "json", "secret": secret}}
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
				return strconv.FormatInt(mirror.ID, 10), nil
			}
		}
		var created struct {
			ID int64 `json:"id"`
		}
		err = api.Do(ctx, http.MethodPost, path, map[string]any{"remote_address": v.Spec.DestinationURL, "remote_password": credential, "interval": v.Spec.Interval, "sync_on_commit": v.Spec.SyncOnCommit}, &created)
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
	var path string
	switch v := object.(type) {
	case *forgev1.ForgejoTeam:
		path = "teams/" + id
	case *forgev1.ForgejoMembership:
		path = "orgs/" + esc(v.Spec.Organization) + "/members/" + esc(v.Spec.Username)
	case *forgev1.ForgejoRobotAccount:
		path = "admin/users/" + esc(v.Spec.Username)
	case *forgev1.ForgejoAccessToken:
		path = "users/" + esc(v.Spec.Username) + "/tokens/" + esc(v.Spec.Name)
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
