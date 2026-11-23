package controller

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Exercise Forgejo's own detection and repair API, not an emulation of it.
func TestIntegrationForgejoRepositoryMergeDetection(t *testing.T) {
	f := startForgejo(t)
	h := newOperatorHarness(t, f)
	api := f.client(t, f.providerToken)
	ctx := context.Background()
	const name = "merge-detection"
	path := "repos/" + integrationAdmin + "/" + name
	if err := api.Do(ctx, http.MethodPost, "user/repos", map[string]any{
		"name": name, "auto_init": true, "default_branch": "main",
	}, nil); err != nil {
		t.Fatal(err)
	}
	off, on := false, true
	object := &forgev1.ForgejoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: integrationNamespace},
		Spec: forgev1.RepositorySpec{
			CommonSpec: forgev1.CommonSpec{ProviderRef: "default"},
			Owner:      integrationAdmin, Name: name,
			AllowManualMerge: &off, AutodetectManualMerge: &off,
		},
	}
	if err := h.kube.Create(ctx, object); err != nil {
		t.Fatal(err)
	}
	r := RepositoryReconciler{Reconciler: Reconciler{Client: h.kube, Transport: statusLog{t}}}
	reconcile := func() {
		t.Helper()
		key := client.ObjectKeyFromObject(object)
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatal(err)
		}
		if err := h.kube.Get(ctx, key, object); err != nil {
			t.Fatal(err)
		}
		ready := meta.FindStatusCondition(object.Status.Conditions, "Ready")
		if ready == nil || ready.Status != metav1.ConditionTrue {
			t.Fatalf("repository not Ready: %+v", object.Status)
		}
	}
	settings := func(manual, detect *bool) {
		t.Helper()
		object.Spec.AllowManualMerge, object.Spec.AutodetectManualMerge = manual, detect
		if err := h.kube.Update(ctx, object); err != nil {
			t.Fatal(err)
		}
		reconcile()
	}
	reconcile()

	parent := t.TempDir()
	dir := filepath.Join(parent, "checkout")
	git := func(workdir string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", workdir}, args...)...)
		// Throwaway account credentials stay out of command arguments and logs.
		basic := base64.StdEncoding.EncodeToString([]byte(integrationAdmin + ":" + integrationPassword))
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_COUNT=3",
			"GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: Basic "+basic,
			"GIT_CONFIG_KEY_1=user.name", "GIT_CONFIG_VALUE_1=Integration",
			"GIT_CONFIG_KEY_2=user.email", "GIT_CONFIG_VALUE_2="+integrationAdmin+"@example.invalid")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
		}
		return strings.TrimSpace(string(out))
	}
	git(parent, "clone", "--quiet", f.url+"/"+integrationAdmin+"/"+name+".git", dir)
	type pull struct {
		Number int    `json:"number"`
		State  string `json:"state"`
		Merged bool   `json:"merged"`
		Commit string `json:"merge_commit_sha"`
	}
	readPull := func(n int) pull {
		t.Helper()
		var p pull
		if err := api.Do(ctx, http.MethodGet, fmt.Sprintf("%s/pulls/%d", path, n), nil, &p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	feature := func(branch string) int {
		t.Helper()
		git(dir, "checkout", "-b", branch, "main")
		file := branch + ".txt"
		if err := os.WriteFile(filepath.Join(dir, file), []byte(branch+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		git(dir, "add", file)
		git(dir, "commit", "-m", branch)
		git(dir, "push", "origin", branch)
		var p pull
		if err := api.Do(ctx, http.MethodPost, path+"/pulls", map[string]any{
			"title": branch, "head": branch, "base": "main",
		}, &p); err != nil {
			t.Fatal(err)
		}
		return p.Number
	}
	land := func(branch string) string {
		t.Helper()
		git(dir, "checkout", "main")
		git(dir, "merge", "--no-ff", "-m", "land "+branch, branch)
		sha := git(dir, "rev-parse", "HEAD")
		git(dir, "push", "origin", "main")
		return sha
	}

	// Reproduce the queue's fallback: Git landed the commit, but metadata was
	// not detected and the PR was closed. Native repair must not move main.
	n := feature("first")
	first := land("first")
	if readPull(n).Merged {
		t.Fatal("merge detection was not disabled")
	}
	if err := api.Do(ctx, http.MethodPatch, fmt.Sprintf("%s/pulls/%d", path, n), map[string]any{"state": "closed"}, nil); err != nil {
		t.Fatal(err)
	}
	settings(&on, &off)
	if err := api.Do(ctx, http.MethodPatch, fmt.Sprintf("%s/pulls/%d", path, n), map[string]any{"state": "open"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := api.Do(ctx, http.MethodPost, fmt.Sprintf("%s/pulls/%d/merge", path, n), map[string]any{
		"Do": "manually-merged", "MergeCommitID": first,
	}, nil); err != nil {
		t.Fatal(err)
	}
	if p := readPull(n); !p.Merged || p.State != "closed" || p.Commit != first {
		t.Fatalf("closed PR was not repaired: %+v", p)
	}
	if remote := git(dir, "ls-remote", "origin", "refs/heads/main"); !strings.HasPrefix(remote, first+"\t") {
		t.Fatalf("repair changed main: %s", remote)
	}

	// Omitted options preserve the enabled settings, and a normal push must
	// now complete a fresh PR without the queue's fallback or a merge API call.
	settings(&on, &on)
	settings(nil, nil)
	n = feature("second")
	second := land("second")
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		p := readPull(n)
		if p.Merged {
			if p.State != "closed" || p.Commit != second {
				t.Fatalf("wrong detected merge: %+v", p)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Forgejo did not detect the Git push: %+v", p)
		}
	}

	// Explicit false is an effective rollback, unlike omission.
	settings(&off, &off)
	n = feature("third")
	err := api.Do(ctx, http.MethodPost, fmt.Sprintf("%s/pulls/%d/merge", path, n), map[string]any{
		"Do": "manually-merged", "MergeCommitID": second,
	}, nil)
	if status := apiStatus(t, err); status != http.StatusMethodNotAllowed {
		t.Fatalf("manual merge was not disabled: HTTP %d", status)
	}
}

func TestIntegrationForgejoRepositoryExternalLinks(t *testing.T) {
	f := startForgejo(t)
	h := newOperatorHarness(t, f)
	api := f.client(t, f.providerToken)
	ctx := context.Background()
	const name = "external-links"
	const website = "https://example.com/docs"
	const wiki = "https://example.com/wiki"
	const trackerURL = "https://example.com/issues"
	const format = "https://example.com/{user}/{repo}/issues/{index}"
	const pattern = "homelab-[a-z0-9]+"
	path := "repos/" + integrationAdmin + "/" + name

	site, wikiURL := website, wiki
	object := &forgev1.ForgejoRepository{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: integrationNamespace},
		Spec: forgev1.RepositorySpec{
			CommonSpec: forgev1.CommonSpec{ProviderRef: "default"},
			Owner:      integrationAdmin, Name: name, Website: &site, ExternalWikiURL: &wikiURL,
			ExternalTracker: &forgev1.RepositoryExternalTracker{
				URL: trackerURL, URLFormat: format, Style: "regexp", RegexpPattern: pattern,
			},
		},
	}
	if err := h.kube.Create(ctx, object); err != nil {
		t.Fatal(err)
	}
	r := RepositoryReconciler{Reconciler: Reconciler{Client: h.kube, Transport: statusLog{t}}}
	type links struct {
		Website      string `json:"website"`
		ExternalWiki *struct {
			URL string `json:"external_wiki_url"`
		} `json:"external_wiki"`
		ExternalTracker *struct {
			URL     string `json:"external_tracker_url"`
			Format  string `json:"external_tracker_format"`
			Style   string `json:"external_tracker_style"`
			Pattern string `json:"external_tracker_regexp_pattern"`
		} `json:"external_tracker"`
		HasIssues bool `json:"has_issues"`
		HasWiki   bool `json:"has_wiki"`
	}
	reconcile := func() links {
		t.Helper()
		key := client.ObjectKeyFromObject(object)
		if _, err := r.Reconcile(ctx, ctrl.Request{NamespacedName: key}); err != nil {
			t.Fatal(err)
		}
		if err := h.kube.Get(ctx, key, object); err != nil {
			t.Fatal(err)
		}
		if !meta.IsStatusConditionTrue(object.Status.Conditions, "Ready") {
			t.Fatalf("repository not Ready: %+v", object.Status.Conditions)
		}
		var remote links
		if err := api.Do(ctx, http.MethodGet, path, nil, &remote); err != nil {
			t.Fatal(err)
		}
		return remote
	}
	assertLinks := func(remote links) {
		t.Helper()
		tracker := remote.ExternalTracker
		if remote.Website != website || remote.ExternalWiki == nil || remote.ExternalWiki.URL != wiki ||
			tracker == nil || tracker.URL != trackerURL || tracker.Format != format ||
			tracker.Style != "regexp" || tracker.Pattern != pattern {
			t.Fatalf("unexpected repository links: %+v", remote)
		}
	}
	assertLinks(reconcile())

	// Include an unrelated PATCH when the link fields become unmanaged.
	object.Spec.Website, object.Spec.ExternalWikiURL, object.Spec.ExternalTracker = nil, nil, nil
	object.Spec.Description = "Operator link test"
	if err := h.kube.Update(ctx, object); err != nil {
		t.Fatal(err)
	}
	assertLinks(reconcile())

	empty := ""
	object.Spec.Website, object.Spec.ExternalWikiURL = &empty, &empty
	object.Spec.ExternalTracker = &forgev1.RepositoryExternalTracker{}
	if err := h.kube.Update(ctx, object); err != nil {
		t.Fatal(err)
	}
	remote := reconcile()
	if remote.Website != "" || remote.ExternalWiki != nil || remote.ExternalTracker != nil ||
		!remote.HasIssues || !remote.HasWiki {
		t.Fatalf("expected built-in Issues and Wiki with no Website: %+v", remote)
	}
}
