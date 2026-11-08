package controller

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	forgeapi "github.com/jakeschurch/forgejo-operator/internal/forgejo"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// These tests drive the full Reconcile entry point against a real Forgejo,
// because the token endpoints' authentication rules are what a stubbed transport
// cannot prove. They start their own throwaway instance from FORGEJO_BIN (see
// `make integration`) and are skipped when it is unset.

const (
	integrationNamespace = "forgejo"
	integrationAdmin     = "site-admin"
	integrationPassword  = "Throwaway-Integration-Pw1"
)

type forgejoInstance struct {
	bin, config, dir, url string
	providerToken         string
}

func startForgejo(t *testing.T) *forgejoInstance {
	t.Helper()
	bin := os.Getenv("FORGEJO_BIN")
	if bin == "" {
		t.Skip("FORGEJO_BIN is not set")
	}
	dir := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	f := &forgejoInstance{bin: bin, dir: dir, config: filepath.Join(dir, "app.ini"), url: fmt.Sprintf("http://127.0.0.1:%d", port)}
	config := fmt.Sprintf(`WORK_PATH = %s
[server]
HTTP_ADDR = 127.0.0.1
HTTP_PORT = %d
ROOT_URL = %s/
DISABLE_SSH = true
OFFLINE_MODE = true
[database]
DB_TYPE = sqlite3
PATH = %s
[security]
INSTALL_LOCK = true
SECRET_KEY = throwaway-integration-secret-key
PASSWORD_CHECK_PWN = false
[service]
DISABLE_REGISTRATION = true
[log]
MODE = file
ROOT_PATH = %s
[cron.update_checker]
ENABLED = false
[federation]
ENABLED = false
`, dir, port, f.url, filepath.Join(dir, "forgejo.db"), filepath.Join(dir, "log"))
	if err := os.WriteFile(f.config, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := f.command("web")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	anonymous := f.client(t, "")
	var version struct {
		Version string `json:"version"`
	}
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		if err := anonymous.Do(context.Background(), http.MethodGet, "version", nil, &version); err == nil {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("Forgejo did not start: %v", err)
		}
	}
	t.Logf("Forgejo %s at %s", version.Version, f.url)
	f.createUser(t, integrationAdmin, "--admin")
	var created struct {
		SHA1 string `json:"sha1"`
	}
	path := "users/" + integrationAdmin + "/tokens"
	// The same shape as a provider's token: an admin's API token, not a password.
	if err := anonymous.DoBasic(context.Background(), http.MethodPost, path, integrationAdmin, integrationPassword, map[string]any{"name": "provider", "scopes": []string{"write:admin", "write:user", "write:repository", "write:organization"}}, &created); err != nil {
		t.Fatal(err)
	}
	f.providerToken = created.SHA1
	return f
}

func (f *forgejoInstance) command(args ...string) *exec.Cmd {
	cmd := exec.Command(f.bin, append([]string{"--config", f.config, "--work-path", f.dir, "--custom-path", filepath.Join(f.dir, "custom")}, args...)...)
	cmd.Dir = f.dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + f.dir, "USER=" + os.Getenv("USER")}
	return cmd
}

func (f *forgejoInstance) createUser(t *testing.T, username string, extra ...string) {
	t.Helper()
	args := append([]string{"admin", "user", "create", "--username", username, "--password", integrationPassword, "--email", username + "@example.invalid", "--must-change-password=false"}, extra...)
	if out, err := f.command(args...).CombinedOutput(); err != nil {
		t.Fatalf("create user %s: %v: %s", username, err, out)
	}
}

func (f *forgejoInstance) client(t *testing.T, token string) *forgeapi.Client {
	t.Helper()
	api, err := forgeapi.New(f.url, token, forgeapi.WithRetries(0), forgeapi.WithRateLimit(1000))
	if err != nil {
		t.Fatal(err)
	}
	return api
}

// tokenLogin returns what using a token yields: its login, or the HTTP status.
func (f *forgejoInstance) tokenLogin(t *testing.T, token string) (string, int) {
	t.Helper()
	var user struct {
		Login string `json:"login"`
	}
	err := f.client(t, token).Do(context.Background(), http.MethodGet, "user", nil, &user)
	if err != nil {
		return "", apiStatus(t, err)
	}
	return user.Login, http.StatusOK
}

func (f *forgejoInstance) tokenNames(t *testing.T, username string) []string {
	t.Helper()
	var tokens []struct {
		Name string `json:"name"`
	}
	path := "users/" + username + "/tokens?limit=50"
	if err := f.client(t, "").DoBasic(context.Background(), http.MethodGet, path, integrationAdmin, integrationPassword, nil, &tokens); err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(tokens))
	for _, token := range tokens {
		names = append(names, token.Name)
	}
	return names
}

func apiStatus(t *testing.T, err error) int {
	t.Helper()
	var apiErr *forgeapi.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("not an API error: %v", err)
	}
	return apiErr.StatusCode
}

// statusLog records each request's outcome. It holds no credentials.
type statusLog struct{ t *testing.T }

func (l statusLog) RoundTrip(r *http.Request) (*http.Response, error) {
	auth, _, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err == nil {
		l.t.Logf("%s %s auth=%s -> %d", r.Method, r.URL.Path, auth, resp.StatusCode)
	}
	return resp, err
}

type operatorHarness struct {
	t      *testing.T
	f      *forgejoInstance
	kube   client.Client
	tokens *managedReconciler
	robots *managedReconciler
}

func newOperatorHarness(t *testing.T, f *forgejoInstance, allowed ...string) *operatorHarness {
	t.Helper()
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme)
	_ = forgev1.AddToScheme(scheme)
	kube := fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&forgev1.ForgejoAccessToken{}, &forgev1.ForgejoRobotAccount{}, &forgev1.ForgejoRepository{}).
		WithObjects(
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "provider-token", Namespace: integrationNamespace},
				Data:       map[string][]byte{"token": []byte(f.providerToken)},
			},
			&corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{Name: "mint-admin", Namespace: integrationNamespace},
				Data:       map[string][]byte{"username": []byte(integrationAdmin), "password": []byte(integrationPassword)},
			},
			&forgev1.ForgejoProvider{
				ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: integrationNamespace},
				Spec: forgev1.ForgejoProviderSpec{
					URL:            f.url,
					TokenSecretRef: corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "provider-token"}, Key: "token"},
					HumanAccessTokens: &forgev1.HumanAccessTokenPolicy{
						AllowedUsernames:          allowed,
						AdminCredentialsSecretRef: corev1.LocalObjectReference{Name: "mint-admin"},
					},
				},
			},
		).Build()
	base := Reconciler{Client: kube, Transport: statusLog{t}}
	return &operatorHarness{
		t: t, f: f, kube: kube,
		tokens: &managedReconciler{Reconciler: base, newObject: func() client.Object { return &forgev1.ForgejoAccessToken{} }},
		robots: &managedReconciler{Reconciler: base, newObject: func() client.Object { return &forgev1.ForgejoRobotAccount{} }},
	}
}

func (h *operatorHarness) reconcileToken(name string) {
	h.t.Helper()
	request := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: integrationNamespace, Name: name}}
	if _, err := h.tokens.Reconcile(context.Background(), request); err != nil {
		h.t.Fatal(err)
	}
}

func (h *operatorHarness) reconcileRobot(name string) {
	h.t.Helper()
	request := ctrl.Request{NamespacedName: types.NamespacedName{Namespace: integrationNamespace, Name: name}}
	if _, err := h.robots.Reconcile(context.Background(), request); err != nil {
		h.t.Fatal(err)
	}
}

func (h *operatorHarness) createToken(object *forgev1.ForgejoAccessToken) {
	h.t.Helper()
	object.Namespace = integrationNamespace
	object.Spec.ProviderRef = "default"
	object.Spec.DeletionPolicy = forgev1.DeletionPolicyDelete
	if object.Spec.Scopes == nil {
		object.Spec.Scopes = []string{"read:user"}
	}
	if err := h.kube.Create(context.Background(), object); err != nil {
		h.t.Fatal(err)
	}
}

func (h *operatorHarness) getToken(name string) *forgev1.ForgejoAccessToken {
	h.t.Helper()
	var stored forgev1.ForgejoAccessToken
	if err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: integrationNamespace, Name: name}, &stored); err != nil {
		h.t.Fatal(err)
	}
	return &stored
}

func (h *operatorHarness) requireReady(name string) *forgev1.ForgejoAccessToken {
	h.t.Helper()
	stored := h.getToken(name)
	ready := meta.FindStatusCondition(stored.Status.Conditions, "Ready")
	if ready == nil || ready.Status != metav1.ConditionTrue {
		h.t.Fatalf("%s is not Ready: %+v", name, ready)
	}
	return stored
}

func (h *operatorHarness) secretToken(name string) string {
	h.t.Helper()
	var secret corev1.Secret
	if err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: integrationNamespace, Name: name}, &secret); err != nil {
		h.t.Fatal(err)
	}
	return string(secret.Data["token"])
}

func (h *operatorHarness) rotate(name, nonce string) {
	h.t.Helper()
	stored := h.getToken(name)
	stored.Spec.RotationNonce = nonce
	if err := h.kube.Update(context.Background(), stored); err != nil {
		h.t.Fatal(err)
	}
	h.reconcileToken(name)
}

// deleteToken asserts deletion finished: the finalizer ran and the CR and its
// generated Secret are gone.
func (h *operatorHarness) deleteToken(name, secretName string) {
	h.t.Helper()
	if err := h.kube.Delete(context.Background(), h.getToken(name)); err != nil {
		h.t.Fatal(err)
	}
	h.reconcileToken(name)
	var stored forgev1.ForgejoAccessToken
	err := h.kube.Get(context.Background(), client.ObjectKey{Namespace: integrationNamespace, Name: name}, &stored)
	if !apierrors.IsNotFound(err) {
		h.t.Fatalf("%s was not finalized (err=%v), conditions: %+v", name, err, stored.Status.Conditions)
	}
	var secret corev1.Secret
	err = h.kube.Get(context.Background(), client.ObjectKey{Namespace: integrationNamespace, Name: secretName}, &secret)
	if !apierrors.IsNotFound(err) {
		h.t.Fatalf("Secret %s survived deletion: %v", secretName, err)
	}
}

func (h *operatorHarness) requireToken(token, login string) {
	h.t.Helper()
	if got, status := h.f.tokenLogin(h.t, token); got != login || status != http.StatusOK {
		h.t.Fatalf("token: login=%q status=%d, want %q", got, status, login)
	}
}

func (h *operatorHarness) requireRevoked(token string) {
	h.t.Helper()
	if _, status := h.f.tokenLogin(h.t, token); status != http.StatusUnauthorized {
		h.t.Fatalf("revoked token: status=%d, want 401", status)
	}
}

// createRobot goes through the operator, so the password is the generated one.
func (h *operatorHarness) createRobot(name string, policy forgev1.DeletionPolicy) {
	h.t.Helper()
	robot := &forgev1.ForgejoRobotAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: integrationNamespace},
		Spec: forgev1.RobotAccountSpec{
			CommonSpec: forgev1.CommonSpec{ProviderRef: "default", DeletionPolicy: policy},
			Username:   name, Email: name + "@example.invalid",
		},
	}
	if err := h.kube.Create(context.Background(), robot); err != nil {
		h.t.Fatal(err)
	}
	h.reconcileRobot(name)
	if err := h.kube.Get(context.Background(), client.ObjectKeyFromObject(robot), robot); err != nil {
		h.t.Fatal(err)
	}
	if ready := meta.FindStatusCondition(robot.Status.Conditions, "Ready"); ready == nil || ready.Status != metav1.ConditionTrue {
		h.t.Fatalf("robot %s is not Ready: %+v", name, ready)
	}
}

func TestIntegrationForgejoHumanAccessToken(t *testing.T) {
	f := startForgejo(t)
	f.createUser(t, "jake")
	api := f.client(t, f.providerToken)
	ctx := context.Background()

	t.Run("provider token cannot manage another user's tokens", func(t *testing.T) {
		mint := map[string]any{"name": "via-token", "scopes": []string{"read:user"}}
		if status := apiStatus(t, api.Do(ctx, http.MethodPost, "users/jake/tokens", mint, nil)); status != http.StatusUnauthorized {
			t.Fatalf("POST with admin token: %d", status)
		}
		if status := apiStatus(t, api.Do(ctx, http.MethodDelete, "users/jake/tokens/1", nil, nil)); status != http.StatusUnauthorized {
			t.Fatalf("DELETE with admin token: %d", status)
		}
	})

	t.Run("mint, scope, rotate, delete", func(t *testing.T) {
		h := newOperatorHarness(t, f, "jake")
		var before map[string]any
		if err := api.Do(ctx, http.MethodGet, "users/jake", nil, &before); err != nil {
			t.Fatal(err)
		}
		h.createToken(&forgev1.ForgejoAccessToken{
			ObjectMeta: metav1.ObjectMeta{Name: "workstation"},
			Spec:       forgev1.AccessTokenSpec{AccountType: forgev1.AccessTokenAccountHuman, Username: "jake", Name: "workstation", SecretName: "workstation-token"},
		})
		h.reconcileToken("workstation")
		h.reconcileToken("workstation")
		first := h.requireReady("workstation")
		firstID := first.Status.RemoteID
		if _, err := strconv.ParseInt(firstID, 10, 64); err != nil {
			t.Fatalf("remote id %q is not a token id", firstID)
		}
		token := h.secretToken("workstation-token")
		h.requireToken(token, "jake")
		minted := f.client(t, token)
		if status := apiStatus(t, minted.Do(ctx, http.MethodPost, "user/repos", map[string]any{"name": "out-of-scope"}, nil)); status != http.StatusForbidden {
			t.Fatalf("out-of-scope request: %d", status)
		}

		h.rotate("workstation", "2")
		rotated := h.requireReady("workstation")
		if rotated.Status.RemoteID == firstID {
			t.Fatalf("remote id did not change: %s", firstID)
		}
		next := h.secretToken("workstation-token")
		h.requireRevoked(token)
		h.requireToken(next, "jake")

		h.deleteToken("workstation", "workstation-token")
		h.requireRevoked(next)
		if names := f.tokenNames(t, "jake"); len(names) != 0 {
			t.Fatalf("tokens left on the account: %v", names)
		}

		// The account itself: the person still signs in, and nothing else moved.
		if err := f.client(t, "").DoBasic(ctx, http.MethodGet, "user", "jake", integrationPassword, nil, nil); err != nil {
			t.Fatalf("the user's password stopped working: %v", err)
		}
		var after map[string]any
		if err := api.Do(ctx, http.MethodGet, "users/jake", nil, &after); err != nil {
			t.Fatal(err)
		}
		if fmt.Sprint(before) != fmt.Sprint(after) {
			t.Fatalf("account changed:\nbefore %v\nafter  %v", before, after)
		}
	})

	t.Run("a token the person made is never touched", func(t *testing.T) {
		h := newOperatorHarness(t, f, "jake")
		var own struct {
			SHA1 string `json:"sha1"`
		}
		if err := f.client(t, "").DoBasic(ctx, http.MethodPost, "users/jake/tokens", "jake", integrationPassword, map[string]any{"name": "mine", "scopes": []string{"read:user"}}, &own); err != nil {
			t.Fatal(err)
		}
		h.createToken(&forgev1.ForgejoAccessToken{
			ObjectMeta: metav1.ObjectMeta{Name: "collision"},
			Spec:       forgev1.AccessTokenSpec{AccountType: forgev1.AccessTokenAccountHuman, Username: "jake", Name: "mine", SecretName: "collision-token"},
		})
		h.reconcileToken("collision")
		degraded := meta.FindStatusCondition(h.getToken("collision").Status.Conditions, "Degraded")
		if degraded == nil || degraded.Status != metav1.ConditionTrue || !strings.Contains(degraded.Message, "already used") {
			t.Fatalf("degraded=%+v", degraded)
		}
		h.requireToken(own.SHA1, "jake")
	})
}

func TestIntegrationForgejoRobotAccessToken(t *testing.T) {
	f := startForgejo(t)
	ctx := context.Background()

	t.Run("rotate", func(t *testing.T) {
		h := newOperatorHarness(t, f)
		h.createRobot("ci-rotate", forgev1.DeletionPolicyOrphan)
		h.createToken(&forgev1.ForgejoAccessToken{
			ObjectMeta: metav1.ObjectMeta{Name: "rotate"},
			Spec:       forgev1.AccessTokenSpec{Username: "ci-rotate", Name: "reader", SecretName: "rotate-token"},
		})
		h.reconcileToken("rotate")
		// A second pass leaves the status a deployed CR would have.
		h.reconcileToken("rotate")
		h.requireReady("rotate")
		token := h.secretToken("rotate-token")
		h.requireToken(token, "ci-rotate")

		h.rotate("rotate", "2")
		h.requireReady("rotate")
		next := h.secretToken("rotate-token")
		if next == token {
			t.Fatal("token did not rotate")
		}
		h.requireRevoked(token)
		h.requireToken(next, "ci-rotate")
	})

	t.Run("delete", func(t *testing.T) {
		h := newOperatorHarness(t, f)
		h.createRobot("ci-delete", forgev1.DeletionPolicyOrphan)
		h.createToken(&forgev1.ForgejoAccessToken{
			ObjectMeta: metav1.ObjectMeta{Name: "delete"},
			Spec:       forgev1.AccessTokenSpec{Username: "ci-delete", Name: "reader", SecretName: "delete-token"},
		})
		h.reconcileToken("delete")
		h.reconcileToken("delete")
		token := h.secretToken("delete-token")
		h.requireToken(token, "ci-delete")

		h.deleteToken("delete", "delete-token")
		h.requireRevoked(token)
		if names := f.tokenNames(t, "ci-delete"); len(names) != 0 {
			t.Fatalf("tokens left on the account: %v", names)
		}
	})

	// Forgejo reads a numeric path segment as an id, so addressing a token named
	// after another token's id by name would revoke the wrong one.
	t.Run("a numeric name addresses only that token", func(t *testing.T) {
		h := newOperatorHarness(t, f)
		h.createRobot("ci-numeric", forgev1.DeletionPolicyOrphan)
		var secret corev1.Secret
		if err := h.kube.Get(ctx, client.ObjectKey{Namespace: integrationNamespace, Name: "ci-numeric-password"}, &secret); err != nil {
			t.Fatal(err)
		}
		var decoy struct {
			ID   int64  `json:"id"`
			SHA1 string `json:"sha1"`
		}
		if err := f.client(t, "").DoBasic(ctx, http.MethodPost, "users/ci-numeric/tokens", "ci-numeric", string(secret.Data["password"]), map[string]any{"name": "decoy", "scopes": []string{"read:user"}}, &decoy); err != nil {
			t.Fatal(err)
		}
		h.createToken(&forgev1.ForgejoAccessToken{
			ObjectMeta: metav1.ObjectMeta{Name: "numeric"},
			Spec:       forgev1.AccessTokenSpec{Username: "ci-numeric", Name: strconv.FormatInt(decoy.ID, 10), SecretName: "numeric-token"},
		})
		h.reconcileToken("numeric")
		h.reconcileToken("numeric")
		token := h.secretToken("numeric-token")

		h.rotate("numeric", "2")
		h.requireReady("numeric")
		next := h.secretToken("numeric-token")
		h.requireRevoked(token)
		h.requireToken(next, "ci-numeric")
		h.requireToken(decoy.SHA1, "ci-numeric")

		h.deleteToken("numeric", "numeric-token")
		h.requireRevoked(next)
		h.requireToken(decoy.SHA1, "ci-numeric")
	})

	// A robot deleted first takes its password and its tokens with it, so there
	// is nothing left to authenticate as and nothing left to revoke.
	t.Run("delete after the robot is gone", func(t *testing.T) {
		h := newOperatorHarness(t, f)
		h.createRobot("ci-gone", forgev1.DeletionPolicyDelete)
		h.createToken(&forgev1.ForgejoAccessToken{
			ObjectMeta: metav1.ObjectMeta{Name: "gone"},
			Spec:       forgev1.AccessTokenSpec{Username: "ci-gone", Name: "reader", SecretName: "gone-token"},
		})
		h.reconcileToken("gone")
		token := h.secretToken("gone-token")

		var robot forgev1.ForgejoRobotAccount
		key := client.ObjectKey{Namespace: integrationNamespace, Name: "ci-gone"}
		if err := h.kube.Get(ctx, key, &robot); err != nil {
			t.Fatal(err)
		}
		if err := h.kube.Delete(ctx, &robot); err != nil {
			t.Fatal(err)
		}
		h.reconcileRobot("ci-gone")
		if err := h.kube.Get(ctx, key, &robot); !apierrors.IsNotFound(err) {
			t.Fatalf("robot was not finalized: %v", err)
		}
		h.requireRevoked(token)
		h.deleteToken("gone", "gone-token")
	})

	// The orphaned robot still exists, but its password can no longer be found.
	// The token must not be silently leaked, and the reason must be visible.
	t.Run("delete without a usable robot credential reports it", func(t *testing.T) {
		h := newOperatorHarness(t, f)
		h.createRobot("ci-orphan", forgev1.DeletionPolicyOrphan)
		h.createToken(&forgev1.ForgejoAccessToken{
			ObjectMeta: metav1.ObjectMeta{Name: "orphan"},
			Spec:       forgev1.AccessTokenSpec{Username: "ci-orphan", Name: "reader", SecretName: "orphan-token"},
		})
		h.reconcileToken("orphan")
		token := h.secretToken("orphan-token")
		var robot forgev1.ForgejoRobotAccount
		if err := h.kube.Get(ctx, client.ObjectKey{Namespace: integrationNamespace, Name: "ci-orphan"}, &robot); err != nil {
			t.Fatal(err)
		}
		if err := h.kube.Delete(ctx, &robot); err != nil {
			t.Fatal(err)
		}
		if err := h.kube.Delete(ctx, h.getToken("orphan")); err != nil {
			t.Fatal(err)
		}
		h.reconcileToken("orphan")
		stored := h.getToken("orphan")
		degraded := meta.FindStatusCondition(stored.Status.Conditions, "Degraded")
		if degraded == nil || degraded.Status != metav1.ConditionTrue {
			t.Fatalf("degraded=%+v", degraded)
		}
		t.Logf("reported: %s", degraded.Message)
		h.requireToken(token, "ci-orphan")
	})
}
