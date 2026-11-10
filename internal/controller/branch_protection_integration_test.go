package controller

import (
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIntegrationBranchProtectionEnforcesChecksAndAllowsQueuePush(t *testing.T) {
	f := startForgejo(t)
	harness := newOperatorHarness(t, f)
	api := f.client(t, f.providerToken)
	ctx := context.Background()
	const name = "required-checks"
	path := "repos/" + integrationAdmin + "/" + name
	if err := api.Do(ctx, http.MethodPost, "user/repos", map[string]any{"name": name, "auto_init": true, "default_branch": "main"}, nil); err != nil {
		t.Fatal(err)
	}
	object := &forgev1.ForgejoBranchProtection{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: integrationNamespace},
		Spec:       forgev1.BranchProtectionSpec{CommonSpec: forgev1.CommonSpec{ProviderRef: "default"}, Owner: integrationAdmin, Repository: name, Branch: "main", RequiredStatusContexts: []string{"margo/required-checks"}, EnablePush: true, EnableMerge: true},
	}
	reconciler := &managedReconciler{Reconciler: Reconciler{Client: harness.kube}}
	reconcile := func(want bool) {
		t.Helper()
		if _, err := reconciler.reconcile(ctx, api, object); err != nil {
			t.Fatal(err)
		}
		var protection struct {
			EnableStatusCheck bool     `json:"enable_status_check"`
			Contexts          []string `json:"status_check_contexts"`
		}
		if err := api.Do(ctx, http.MethodGet, path+"/branch_protections/main", nil, &protection); err != nil {
			t.Fatal(err)
		}
		if protection.EnableStatusCheck != want || len(protection.Contexts) != len(object.Spec.RequiredStatusContexts) {
			t.Fatalf("required checks not reconciled: %+v", protection)
		}
	}
	reconcile(true)
	parent := t.TempDir()
	directory := filepath.Join(parent, "checkout")
	git := func(workdir string, arguments ...string) string {
		t.Helper()
		command := exec.Command("git", append([]string{"-C", workdir}, arguments...)...)
		basic := base64.StdEncoding.EncodeToString([]byte(integrationAdmin + ":" + integrationPassword))
		command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_COUNT=3", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: Basic "+basic, "GIT_CONFIG_KEY_1=user.name", "GIT_CONFIG_VALUE_1=Integration", "GIT_CONFIG_KEY_2=user.email", "GIT_CONFIG_VALUE_2=integration@example.invalid")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(arguments, " "), err, output)
		}
		return strings.TrimSpace(string(output))
	}
	git(parent, "clone", "--quiet", f.url+"/"+integrationAdmin+"/"+name+".git", directory)
	git(directory, "checkout", "-b", "candidate")
	if err := os.WriteFile(filepath.Join(directory, "candidate.txt"), []byte("candidate\n"), 0600); err != nil {
		t.Fatal(err)
	}
	git(directory, "add", "candidate.txt")
	git(directory, "commit", "-m", "candidate")
	revision := git(directory, "rev-parse", "HEAD")
	git(directory, "push", "origin", "candidate")
	var pull struct {
		Number int `json:"number"`
	}
	if err := api.Do(ctx, http.MethodPost, path+"/pulls", map[string]any{"title": "candidate", "head": "candidate", "base": "main"}, &pull); err != nil {
		t.Fatal(err)
	}
	mergePath := path + "/pulls/1/merge"
	if pull.Number != 1 {
		t.Fatalf("unexpected pull number %d", pull.Number)
	}
	err := api.Do(ctx, http.MethodPost, mergePath, map[string]any{"Do": "merge", "head_commit_id": revision, "force_merge": false}, nil)
	if err == nil {
		t.Fatal("unchecked pull request merged")
	}
	if status := apiStatus(t, err); status != http.StatusMethodNotAllowed {
		t.Fatalf("unchecked merge returned HTTP %d", status)
	}
	t.Logf("unchecked native merge blocked: %v", err)
	if err := api.Do(ctx, http.MethodPost, path+"/statuses/"+revision, map[string]any{"context": "margo/required-checks", "state": "success"}, nil); err != nil {
		t.Fatal(err)
	}
	err = api.Do(ctx, http.MethodPost, mergePath, map[string]any{"Do": "merge", "head_commit_id": revision, "force_merge": false}, nil)
	if err == nil {
		t.Fatal("native merge bypassed the queue-only merge whitelist")
	}
	if status := apiStatus(t, err); status != http.StatusMethodNotAllowed {
		t.Fatalf("queue-only merge returned HTTP %d", status)
	}
	git(directory, "checkout", "main")
	git(directory, "merge", "--no-ff", "-m", "queue landing", "candidate")
	landed := git(directory, "rev-parse", "HEAD")
	git(directory, "push", "origin", "main")
	if remote := git(directory, "ls-remote", "origin", "refs/heads/main"); !strings.HasPrefix(remote, landed+"\t") {
		t.Fatalf("queue push did not land: %s", remote)
	}
	object.Spec.RequiredStatusContexts = nil
	reconcile(false)
}

// A push allowlist must hold against real Forgejo: the allowlisted bot pushes
// the protected branch directly, and any other writer (here the site admin) is
// refused and has to land through a pull request.
func TestIntegrationBranchProtectionPushAllowlist(t *testing.T) {
	f := startForgejo(t)
	harness := newOperatorHarness(t, f)
	api := f.client(t, f.providerToken)
	ctx := context.Background()
	const name, bot = "push-allowlist", "allowed-bot"
	path := "repos/" + integrationAdmin + "/" + name
	if err := api.Do(ctx, http.MethodPost, "user/repos", map[string]any{"name": name, "auto_init": true, "default_branch": "main"}, nil); err != nil {
		t.Fatal(err)
	}
	f.createUser(t, bot)
	if err := api.Do(ctx, http.MethodPut, path+"/collaborators/"+bot, map[string]any{"permission": "write"}, nil); err != nil {
		t.Fatal(err)
	}
	object := &forgev1.ForgejoBranchProtection{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: integrationNamespace},
		Spec:       forgev1.BranchProtectionSpec{CommonSpec: forgev1.CommonSpec{ProviderRef: "default"}, Owner: integrationAdmin, Repository: name, Branch: "main", EnablePush: true, PushAllowlistUsers: []string{bot}},
	}
	reconciler := &managedReconciler{Reconciler: Reconciler{Client: harness.kube}}
	if _, err := reconciler.reconcile(ctx, api, object); err != nil {
		t.Fatal(err)
	}
	var protection struct {
		EnablePushWhitelist bool     `json:"enable_push_whitelist"`
		Usernames           []string `json:"push_whitelist_usernames"`
	}
	if err := api.Do(ctx, http.MethodGet, path+"/branch_protections/main", nil, &protection); err != nil {
		t.Fatal(err)
	}
	if !protection.EnablePushWhitelist || len(protection.Usernames) != 1 || protection.Usernames[0] != bot {
		t.Fatalf("push allowlist not reconciled: %+v", protection)
	}
	parent := t.TempDir()
	push := func(user, file string) error {
		t.Helper()
		directory := filepath.Join(parent, user)
		run := func(arguments ...string) ([]byte, error) {
			command := exec.Command("git", arguments...)
			basic := base64.StdEncoding.EncodeToString([]byte(user + ":" + integrationPassword))
			command.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_COUNT=3", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: Basic "+basic, "GIT_CONFIG_KEY_1=user.name", "GIT_CONFIG_VALUE_1="+user, "GIT_CONFIG_KEY_2=user.email", "GIT_CONFIG_VALUE_2="+user+"@example.invalid")
			return command.CombinedOutput()
		}
		for _, step := range [][]string{
			{"clone", "--quiet", f.url + "/" + integrationAdmin + "/" + name + ".git", directory},
		} {
			if out, err := run(step...); err != nil {
				t.Fatalf("git %v: %v: %s", step, err, out)
			}
		}
		if err := os.WriteFile(filepath.Join(directory, file), []byte(file+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, step := range [][]string{{"-C", directory, "add", file}, {"-C", directory, "commit", "-qm", file}} {
			if out, err := run(step...); err != nil {
				t.Fatalf("git %v: %v: %s", step, err, out)
			}
		}
		out, err := run("-C", directory, "push", "origin", "main")
		t.Logf("%s push: %s", user, out)
		return err
	}
	if err := push(integrationAdmin, "admin.txt"); err == nil {
		t.Fatal("a writer outside the push allowlist pushed the protected branch")
	}
	if err := push(bot, "bot.txt"); err != nil {
		t.Fatalf("allowlisted bot could not push: %v", err)
	}
}
