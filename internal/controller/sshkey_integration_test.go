package controller

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// FORGEJO_BIN points at a disposable local Forgejo; never calls a live service.
func TestIntegrationForgejoSSHKey(t *testing.T) {
	f := startForgejo(t)
	f.createUser(t, "jake")
	f.createUser(t, "other")
	h := newOperatorHarness(t, f)
	ctx := context.Background()
	var provider forgev1.ForgejoProvider
	if err := h.kube.Get(ctx, client.ObjectKey{Namespace: integrationNamespace, Name: "default"}, &provider); err != nil {
		t.Fatal(err)
	}
	provider.Spec.SSHKeys = &forgev1.SSHKeyPolicy{AllowedUsers: []string{"jake", "other", integrationAdmin}, AllowedNamespaces: []string{"elsewhere"}}
	if err := h.kube.Update(ctx, &provider); err != nil {
		t.Fatal(err)
	}
	r := &SSHKeyReconciler{Reconciler: Reconciler{Client: h.kube, Transport: statusLog{t}}}
	reconcile := func(key *forgev1.ForgejoSSHKey) {
		t.Helper()
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(key)}); err != nil {
			t.Fatal(err)
		}
		if err := h.kube.Get(ctx, client.ObjectKeyFromObject(key), key); err != nil {
			t.Fatal(err)
		}
	}
	create := func(name, user string, policy forgev1.DeletionPolicy) *forgev1.ForgejoSSHKey {
		t.Helper()
		key := &forgev1.ForgejoSSHKey{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: integrationNamespace}, Spec: forgev1.SSHKeySpec{
			ProviderRef: "default", User: user, Title: "git signing key", PublicKey: signingKey, DeletionPolicy: policy,
		}}
		if err := h.kube.Create(ctx, key); err != nil {
			t.Fatal(err)
		}
		return key
	}
	api := f.client(t, f.providerToken)

	key := create("jake", "jake", forgev1.DeletionPolicyDelete)
	reconcile(key)
	if !meta.IsStatusConditionTrue(key.Status.Conditions, "Ready") {
		t.Fatalf("key not ready: %+v", key.Status.Conditions)
	}
	// Forgejo agrees on the fingerprint and, as an API-registered key, has not
	// seen the owner's proof of possession.
	if key.Status.Fingerprint != signingKeyFingerprint || (key.Status.Verified != nil && *key.Status.Verified) {
		t.Fatalf("status = %+v", key.Status)
	}
	if c := meta.FindStatusCondition(key.Status.Conditions, "Verified"); c == nil || c.Status == metav1.ConditionTrue {
		t.Fatalf("Verified = %+v", c)
	}
	remote, err := findSSHKey(ctx, api, "jake", signingKeyFingerprint)
	if err != nil || remote == nil || (remote.Verified != nil && *remote.Verified) {
		t.Fatalf("registered key = %+v, %v", remote, err)
	}
	first := key.Status.RemoteID
	reconcile(key)
	if key.Status.RemoteID != first {
		t.Fatalf("idempotent reconcile recreated the key: %s -> %s", first, key.Status.RemoteID)
	}

	// A second CR for the same fingerprint in the namespace is refused locally.
	dup := create("dup", "other", forgev1.DeletionPolicyOrphan)
	reconcile(dup)
	if meta.IsStatusConditionTrue(dup.Status.Conditions, "Ready") {
		t.Fatalf("duplicate claim accepted: %+v", dup.Status.Conditions)
	}
	if err := h.kube.Delete(ctx, dup); err != nil {
		t.Fatal(err)
	}
	// From another namespace, Forgejo itself refuses the key for another
	// account (fingerprints are instance-unique): reported, not stolen.
	clash := &forgev1.ForgejoSSHKey{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "elsewhere"}, Spec: forgev1.SSHKeySpec{
		ProviderRef: "default", ProviderNamespace: integrationNamespace, User: "other", Title: "git signing key", PublicKey: signingKey, DeletionPolicy: forgev1.DeletionPolicyOrphan,
	}}
	if err := h.kube.Create(ctx, clash); err != nil {
		t.Fatal(err)
	}
	reconcile(clash)
	if c := meta.FindStatusCondition(clash.Status.Conditions, "Ready"); c == nil || c.Reason != "KeyInUse" {
		t.Fatalf("clash Ready = %+v", c)
	}

	// Site administrators are refused even when allowlisted.
	admin := &forgev1.ForgejoSSHKey{ObjectMeta: metav1.ObjectMeta{Name: "admin", Namespace: integrationNamespace}, Spec: forgev1.SSHKeySpec{
		ProviderRef: "default", User: integrationAdmin, Title: "x", PublicKey: deployKeyOther, DeletionPolicy: forgev1.DeletionPolicyOrphan,
	}}
	if err := h.kube.Create(ctx, admin); err != nil {
		t.Fatal(err)
	}
	reconcile(admin)
	if c := meta.FindStatusCondition(admin.Status.Conditions, "Ready"); c == nil || c.Reason != "Unauthorized" {
		t.Fatalf("admin Ready = %+v", c)
	}

	if err := h.kube.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(key)}); err != nil {
		t.Fatal(err)
	}
	if err := api.DoSudo(ctx, http.MethodGet, "user/keys/"+first, "jake", nil, nil); apiStatus(t, err) != http.StatusNotFound {
		t.Fatalf("Delete policy left key %s behind", first)
	}
}

// The owner's one-time proof, driven exactly as documented: open the
// verification URL from status, sign the shown token with ssh-keygen under the
// instance domain, submit it. The operator then reports Verified without
// touching the key.
func TestIntegrationForgejoSSHKeyOwnershipProof(t *testing.T) {
	keygen, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Skip("ssh-keygen is not installed")
	}
	f := startForgejo(t)
	f.createUser(t, "jake")
	h := newOperatorHarness(t, f)
	ctx := context.Background()
	var provider forgev1.ForgejoProvider
	if err := h.kube.Get(ctx, client.ObjectKey{Namespace: integrationNamespace, Name: "default"}, &provider); err != nil {
		t.Fatal(err)
	}
	provider.Spec.SSHKeys = &forgev1.SSHKeyPolicy{AllowedUsers: []string{"jake"}}
	if err := h.kube.Update(ctx, &provider); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	private := filepath.Join(dir, "id_ed25519")
	if out, err := exec.Command(keygen, "-q", "-t", "ed25519", "-N", "", "-C", "integration", "-f", private).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	public, err := os.ReadFile(private + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	key := &forgev1.ForgejoSSHKey{ObjectMeta: metav1.ObjectMeta{Name: "jake", Namespace: integrationNamespace}, Spec: forgev1.SSHKeySpec{
		ProviderRef: "default", User: "jake", Title: "git signing key", PublicKey: string(public), DeletionPolicy: forgev1.DeletionPolicyOrphan,
	}}
	if err := h.kube.Create(ctx, key); err != nil {
		t.Fatal(err)
	}
	r := &SSHKeyReconciler{Reconciler: Reconciler{Client: h.kube, Transport: statusLog{t}}}
	reconcile := func() {
		t.Helper()
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(key)}); err != nil {
			t.Fatal(err)
		}
		if err := h.kube.Get(ctx, client.ObjectKeyFromObject(key), key); err != nil {
			t.Fatal(err)
		}
	}
	reconcile()
	if (key.Status.Verified != nil && *key.Status.Verified) || key.Status.VerificationURL == "" {
		t.Fatalf("status = %+v", key.Status)
	}
	registered := key.Status.RemoteID

	// Sign in to the web UI as jake.
	jar, _ := cookiejar.New(nil)
	web := &http.Client{Jar: jar, Timeout: 15 * time.Second}
	csrf := func(page string) string {
		t.Helper()
		resp, err := web.Get(page)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		// Older Forgejo embeds a form token; newer releases rely on
		// cross-origin checks instead, which a same-origin client passes.
		if m := regexp.MustCompile(`name="_csrf" value="([^"]+)"`).FindSubmatch(body); m != nil {
			return string(m[1])
		}
		return ""
	}
	login := url.Values{"_csrf": {csrf(f.url + "/user/login")}, "user_name": {"jake"}, "password": {integrationPassword}}
	if resp, err := web.PostForm(f.url+"/user/login", login); err != nil {
		t.Fatal(err)
	} else {
		resp.Body.Close()
	}
	// The verification URL from status shows the token to sign.
	resp, err := web.Get(key.Status.VerificationURL)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	token := regexp.MustCompile(`echo -n (?:'|&#39;)([0-9a-f]{64})`).FindSubmatch(page)
	if token == nil {
		t.Fatalf("no token on %s", key.Status.VerificationURL)
	}
	// The namespace is Forgejo's DOMAIN setting, which the page names.
	namespace := regexp.MustCompile(`ssh-keygen -Y sign -n (\S+)`).FindSubmatch(page)
	if namespace == nil {
		t.Fatal("no signing namespace on the verification page")
	}
	domain := string(namespace[1])
	sign := exec.Command(keygen, "-Y", "sign", "-n", domain, "-f", private)
	sign.Stdin = bytes.NewReader(token[1])
	signature, err := sign.Output()
	if err != nil {
		t.Fatalf("ssh-keygen -Y sign: %v", err)
	}
	form := url.Values{
		"_csrf": {csrf(key.Status.VerificationURL)}, "type": {"verify_ssh"}, "title": {"none"},
		"content": {string(public)}, "fingerprint": {key.Status.Fingerprint}, "signature": {string(signature)},
	}
	if resp, err := web.PostForm(f.url+"/user/settings/keys", form); err != nil {
		t.Fatal(err)
	} else {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !bytes.Contains(b, []byte("has been verified")) {
			t.Fatalf("Forgejo did not accept the proof: %s", regexp.MustCompile(`(?s)flash-message.{0,300}`).Find(b))
		}
	}

	reconcile()
	if key.Status.RemoteID != registered {
		t.Fatalf("proof changed the key: %s -> %s", registered, key.Status.RemoteID)
	}
	// Forgejo 17 reports the flag; earlier releases do not, and the operator
	// must then say Unknown rather than keep asking for a proof.
	c := meta.FindStatusCondition(key.Status.Conditions, "Verified")
	if key.Status.Verified == nil {
		if c == nil || c.Reason != "VerificationNotReported" {
			t.Fatalf("Verified = %+v", c)
		}
		t.Log("this Forgejo does not report key verification; run with Forgejo 17 to observe it")
		return
	}
	if !*key.Status.Verified || c == nil || c.Status != metav1.ConditionTrue {
		t.Fatalf("after proof: Verified = %+v", c)
	}
}
