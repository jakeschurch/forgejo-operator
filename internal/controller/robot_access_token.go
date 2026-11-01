package controller

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	forgeapi "github.com/jakeschurch/forgejo-operator/internal/forgejo"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	robotTokenPageSize = 50
	// maxRobotTokenPages bounds the listing walk so a server that keeps returning
	// full pages cannot spin the reconcile forever.
	maxRobotTokenPages = 100
)

// robotPassword reads the password of the managed robot a token belongs to.
// Forgejo requires password authentication on an account's token endpoints, and
// this is the credential the operator already holds for robots.
func (r *managedReconciler) robotPassword(ctx context.Context, v *forgev1.ForgejoAccessToken) (string, error) {
	var robots forgev1.ForgejoRobotAccountList
	if err := r.List(ctx, &robots, client.InNamespace(v.Namespace)); err != nil {
		return "", fmt.Errorf("list robot accounts: %w", err)
	}
	for i := range robots.Items {
		robot := &robots.Items[i]
		if robot.Spec.ProviderRef != v.Spec.ProviderRef || robot.Spec.Username != v.Spec.Username {
			continue
		}
		name := robot.Spec.PasswordSecretName
		if name == "" {
			name = robot.Name + "-password"
		}
		password, err := r.secretValue(ctx, v.Namespace, corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: name},
			Key:                  "password",
		}, "password")
		if err != nil {
			return "", fmt.Errorf("read robot credential: %w", err)
		}
		return password, nil
	}
	return "", errors.New("access token username must reference a managed robot account")
}

// findRobotToken returns the id of the token with this exact name, or 0. Tokens
// are addressed by id because Forgejo reads a numeric DELETE path segment as an
// id, so a token named "5" cannot be reached by name and token id 5 could be hit
// instead. status.remoteID cannot supply the id: a reconcile that finds the token
// already stored records username/name there.
func findRobotToken(ctx context.Context, api *forgeapi.Client, username, password, name string) (int64, error) {
	lastFirstID := int64(0)
	for page := 1; page <= maxRobotTokenPages; page++ {
		var tokens []struct {
			ID   int64  `json:"id"`
			Name string `json:"name"`
		}
		path := "users/" + esc(username) + "/tokens?limit=" + strconv.Itoa(robotTokenPageSize) + "&page=" + strconv.Itoa(page)
		if err := api.DoBasic(ctx, http.MethodGet, path, username, password, nil, &tokens); err != nil {
			return 0, err
		}
		// A server that ignores the page parameter repeats the first page forever.
		if len(tokens) == 0 || tokens[0].ID == lastFirstID {
			return 0, nil
		}
		lastFirstID = tokens[0].ID
		for _, token := range tokens {
			if token.Name == name {
				return token.ID, nil
			}
		}
	}
	return 0, errors.New("token listing did not end")
}

// revokeRobotToken removes the token named by the CR. Unlike a human account,
// where only a recorded id may be revoked, the operator owns a robot account, and
// the name is the CR's natural key. A token that is already gone is not an error,
// so a rotation that fails after revoking can simply be retried.
func revokeRobotToken(ctx context.Context, api *forgeapi.Client, v *forgev1.ForgejoAccessToken, password string) error {
	id, err := findRobotToken(ctx, api, v.Spec.Username, password, v.Spec.Name)
	if err != nil || id == 0 {
		return err
	}
	return revokeAccessToken(ctx, api, v, v.Spec.Username, password, strconv.FormatInt(id, 10))
}

// deleteRobotAccessToken revokes as the robot itself. An account that no longer
// exists took its tokens with it, and usually its password Secret too, so that is
// success. Any other failure keeps the finalizer: dropping it would leak a live
// credential that deletionPolicy Delete promised to remove.
func (r *managedReconciler) deleteRobotAccessToken(ctx context.Context, api *forgeapi.Client, v *forgev1.ForgejoAccessToken) error {
	password, err := r.robotPassword(ctx, v)
	if err == nil {
		err = revokeRobotToken(ctx, api, v, password)
	}
	if err == nil {
		return nil
	}
	if isNotFound(api.Do(ctx, http.MethodGet, "users/"+esc(v.Spec.Username), nil, nil)) {
		return nil
	}
	return fmt.Errorf("revoke robot token, which needs the robot's password (set deletionPolicy Orphan to keep the token instead): %w", err)
}
