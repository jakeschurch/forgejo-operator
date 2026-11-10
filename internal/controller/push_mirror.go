package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	forgeapi "github.com/jakeschurch/forgejo-operator/internal/forgejo"
)

const (
	// pushMirrorRefService is the advertisement the rotation guard reads from
	// the destination. It is receive-pack, not upload-pack, because it is the
	// exact set of refs `git push --mirror` sees and can delete. GitHub's
	// upload-pack advertisement also lists every refs/pull/* ref, which a push
	// can never touch and which Forgejo can never hold under the same name, so
	// guarding on it would block every rotation of a repository that has ever
	// had a pull request.
	pushMirrorRefService = "git-receive-pack"
	// maxReportedRefs bounds how many offending refs a Degraded message names.
	maxReportedRefs = 5
	// maxMissingObjectChecks stops the object walk once enough missing objects
	// are found to block the rotation and name them.
	maxMissingObjectChecks = maxReportedRefs
	gitRequestTimeout      = 30 * time.Second
)

// Degraded reasons for a credential rotation the guard refused.
const (
	reasonMirrorSyncFailing                      = "MirrorSyncFailing"
	reasonDestinationRefsUnreadable              = "DestinationRefsUnreadable"
	reasonDestinationHasRefsMissingFromSource    = "DestinationHasRefsMissingFromSource"
	reasonDestinationHasObjectsMissingFromSource = "DestinationHasObjectsMissingFromSource"
)

// pushMirrorRotationBlockedError reports a credential rotation the guard
// refused. Nothing was deleted or recreated; the live mirror is untouched. Its
// ConditionReason surfaces as the Degraded reason and the reconcile requeues.
type pushMirrorRotationBlockedError struct{ reason, message string }

func (e *pushMirrorRotationBlockedError) Error() string {
	return "push mirror credential changed but rotation is blocked, the mirror was left untouched: " + e.message
}
func (e *pushMirrorRotationBlockedError) ConditionReason() string { return e.reason }

type remotePushMirror struct {
	ID            int64  `json:"id"`
	RemoteName    string `json:"remote_name"`
	RemoteAddress string `json:"remote_address"`
	LastError     string `json:"last_error"`
}

// pushMirrorCredentialHash fingerprints the credential a mirror authenticates
// with. The username is part of it: changing remoteUsername changes what
// Forgejo stores just as much as changing the token does.
func pushMirrorCredentialHash(username, credential string) string {
	sum := sha256.Sum256([]byte(username + "\x00" + credential))
	return hex.EncodeToString(sum[:])
}

func (r *managedReconciler) reconcilePushMirror(ctx context.Context, api *forgeapi.Client, v *forgev1.ForgejoPushMirror) (string, error) {
	credential, err := r.secretValue(ctx, v.Namespace, v.Spec.CredentialsSecretRef, "token")
	if err != nil {
		return "", err
	}
	hash := pushMirrorCredentialHash(v.Spec.RemoteUsername, credential)
	base := repoPath(v.Spec.Owner, v.Spec.Repository) + "/push_mirrors"
	var mirrors []remotePushMirror
	if err := api.Do(ctx, http.MethodGet, base, nil, &mirrors); err != nil {
		return "", err
	}
	for _, mirror := range mirrors {
		if mirror.RemoteAddress != v.Spec.DestinationURL {
			continue
		}
		id := strconv.FormatInt(mirror.ID, 10)
		// Guarded credential rotation.
		//
		// The credential is a short-lived GitHub App installation token that
		// ESO re-mints into the referenced Secret well before it expires, so
		// the mirror's stored credential has to follow it. Forgejo makes that
		// dangerous, which is why this used to be adopt-only, for three
		// reasons. Each one is now removed:
		//
		// (1) The listing strips credentials from remote_address, so the
		// stored credential cannot be observed and drift cannot be detected.
		// Removed by status.credentialHash: the operator records the hash of
		// the credential it created the mirror with (or, adopting a mirror it
		// did not create, the one it first sees) and compares the Secret's
		// current value against that, never against Forgejo.
		//
		// (2) Forgejo has no PATCH for a mirror, so a new credential means
		// delete-and-recreate, and a new mirror syncs immediately with
		// `git push --mirror`, which deletes every destination ref the source
		// lacks and force-moves every other one to the source's object. On
		// 2026-09-22 a hand-applied credential fix on jake/homelab armed exactly
		// that sync and it deleted 162 refs (82 branches, 80 tags) from
		// github.com/jakeschurch/homelab; they were restored from a local
		// clone. Removed by the guard: before deleting anything the operator
		// reads the destination's receive-pack ref advertisement with the NEW
		// credential and requires every destination ref to exist in Forgejo
		// under the same name AND its object to exist in Forgejo. Then the
		// mirror push can delete no ref and orphan no object that Forgejo does
		// not already hold. The source being ahead of the destination is the
		// normal case and passes.
		//
		// (3) Safe sequencing needed a human comparing both sides. The guard
		// IS that comparison, plus a precondition that the mirror's last sync
		// succeeded (last_error is empty), so a rotation never compounds a
		// mirror that is already failing for some other reason. If either
		// check fails, nothing is deleted or recreated: the resource goes
		// Degraded with a reason naming what blocked it and the reconcile
		// retries, so a human only has to act when the refs really diverge.
		switch v.Status.CredentialHash {
		case "":
			// Adoption or first observation: record, change nothing.
			v.Status.CredentialHash = hash
			return id, nil
		case hash:
			return id, nil
		}
		if err := r.pushMirrorRotationGuard(ctx, api, v, mirror, credential); err != nil {
			return "", err
		}
		if mirror.RemoteName == "" {
			return "", fmt.Errorf("push mirror for %s has no remote_name to delete it by", v.Spec.DestinationURL)
		}
		if err := api.Do(ctx, http.MethodDelete, base+"/"+esc(mirror.RemoteName), nil, nil); err != nil && !isNotFound(err) {
			return "", fmt.Errorf("delete push mirror for rotation: %w", err)
		}
		newID, err := createPushMirror(ctx, api, base, v, credential)
		if err != nil {
			// The next reconcile finds no mirror and creates it.
			return "", fmt.Errorf("recreate push mirror after rotation delete: %w", err)
		}
		// The live mirror now holds the new credential whatever happens next.
		v.Status.CredentialHash = hash
		v.Status.RemoteID = newID
		if err := api.Do(ctx, http.MethodPost, repoPath(v.Spec.Owner, v.Spec.Repository)+"/push_mirrors-sync", nil, nil); err != nil {
			return "", fmt.Errorf("sync rotated push mirror: %w", err)
		}
		return newID, nil
	}
	newID, err := createPushMirror(ctx, api, base, v, credential)
	if err != nil {
		return "", err
	}
	v.Status.CredentialHash = hash
	return newID, nil
}

func createPushMirror(ctx context.Context, api *forgeapi.Client, base string, v *forgev1.ForgejoPushMirror, credential string) (string, error) {
	var created struct {
		ID int64 `json:"id"`
	}
	payload := map[string]any{"remote_address": v.Spec.DestinationURL, "remote_password": credential, "interval": v.Spec.Interval, "sync_on_commit": v.Spec.SyncOnCommit}
	// Only send remote_username when it is declared, so the request stays
	// byte-identical for every mirror that does not set it.
	if v.Spec.RemoteUsername != "" {
		payload["remote_username"] = v.Spec.RemoteUsername
	}
	if err := api.Do(ctx, http.MethodPost, base, payload, &created); err != nil {
		return "", err
	}
	return strconv.FormatInt(created.ID, 10), nil
}

// pushMirrorRotationGuard returns nil only when deleting and recreating the
// mirror cannot destroy anything on the destination that Forgejo lacks.
func (r *managedReconciler) pushMirrorRotationGuard(ctx context.Context, api *forgeapi.Client, v *forgev1.ForgejoPushMirror, mirror remotePushMirror, credential string) error {
	// last_error is deliberately not echoed: it is free text from git and the
	// remote, and is not guaranteed to be credential-free.
	if strings.TrimSpace(mirror.LastError) != "" {
		return &pushMirrorRotationBlockedError{reason: reasonMirrorSyncFailing,
			message: "the mirror's last sync failed (see last_error on the Forgejo push mirror); fix it, or delete the mirror by hand once the destination's refs are reconciled"}
	}
	destination, err := readAdvertisedRefs(ctx, &http.Client{Timeout: gitRequestTimeout, Transport: r.Transport},
		v.Spec.DestinationURL, pushMirrorRefService, v.Spec.RemoteUsername, credential)
	if err != nil {
		return &pushMirrorRotationBlockedError{reason: reasonDestinationRefsUnreadable,
			message: "cannot read the destination's refs with the new credential: " + err.Error()}
	}
	var sourceRefs []struct {
		Ref    string `json:"ref"`
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	repo := repoPath(v.Spec.Owner, v.Spec.Repository)
	if err := api.Do(ctx, http.MethodGet, repo+"/git/refs", nil, &sourceRefs); err != nil && !isNotFound(err) {
		return fmt.Errorf("list source refs: %w", err)
	}
	source := make(map[string]string, len(sourceRefs))
	known := make(map[string]bool, len(sourceRefs))
	for _, ref := range sourceRefs {
		source[ref.Ref] = ref.Object.SHA
		known[ref.Object.SHA] = true
	}
	names := make([]string, 0, len(destination))
	for name := range destination {
		// HEAD is a symref push --mirror never touches; it only pushes refs/*.
		if strings.HasPrefix(name, "refs/") {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	var missingNames []string
	for _, name := range names {
		if _, ok := source[name]; !ok {
			missingNames = append(missingNames, name)
		}
	}
	if len(missingNames) > 0 {
		return &pushMirrorRotationBlockedError{reason: reasonDestinationHasRefsMissingFromSource,
			message: fmt.Sprintf("%d destination ref(s) do not exist in Forgejo and the mirror push would delete them: %s",
				len(missingNames), summarizeRefs(missingNames))}
	}
	var missingObjects []string
	for _, name := range names {
		oid := destination[name]
		if known[oid] {
			continue
		}
		exists, err := sourceHasObject(ctx, api, repo, oid)
		if err != nil {
			return fmt.Errorf("check destination object of %s in source: %w", name, err)
		}
		if exists {
			known[oid] = true
			continue
		}
		missingObjects = append(missingObjects, name)
		if len(missingObjects) >= maxMissingObjectChecks {
			break
		}
	}
	if len(missingObjects) > 0 {
		return &pushMirrorRotationBlockedError{reason: reasonDestinationHasObjectsMissingFromSource,
			message: "destination ref(s) point at objects Forgejo does not have and the mirror push would discard them: " + summarizeRefs(missingObjects)}
	}
	return nil
}

// sourceHasObject reports whether Forgejo holds the commit or annotated tag
// object oid. Forgejo answers git/commits with 200 for a commit (and for a tag,
// which it peels) and 404 for a missing one; git/tags answers 400 for a
// non-tag. Any other answer is an error, so the guard fails closed.
func sourceHasObject(ctx context.Context, api *forgeapi.Client, repo, oid string) (bool, error) {
	if !isObjectID(oid) {
		return false, nil
	}
	err := api.Do(ctx, http.MethodGet, repo+"/git/commits/"+oid+"?stat=false&verification=false&files=false", nil, nil)
	if err == nil {
		return true, nil
	}
	if !isNotFound(err) {
		return false, err
	}
	err = api.Do(ctx, http.MethodGet, repo+"/git/tags/"+oid, nil, nil)
	if err == nil {
		return true, nil
	}
	var apiErr *forgeapi.APIError
	if isNotFound(err) || (errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusBadRequest) {
		return false, nil
	}
	return false, err
}

func summarizeRefs(refs []string) string {
	if len(refs) <= maxReportedRefs {
		return strings.Join(refs, ", ")
	}
	return strings.Join(refs[:maxReportedRefs], ", ") + fmt.Sprintf(" (and %d more)", len(refs)-maxReportedRefs)
}
