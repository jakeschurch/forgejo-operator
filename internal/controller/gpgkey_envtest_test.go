package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// Exercise defaulting, CEL immutability, status journaling and real Kubernetes
// resource versions against a local control plane, with the fake Forgejo API.
func TestGPGEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is not set")
	}
	environment := &envtest.Environment{CRDDirectoryPaths: []string{"../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
	config, err := environment.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := environment.Stop(); err != nil {
			t.Error(err)
		}
	})
	f := newGPGFixture(t)
	if err := rbacv1.AddToScheme(f.r.Scheme()); err != nil {
		t.Fatal(err)
	}
	kube, err := client.New(config, client.Options{Scheme: f.r.Scheme()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, name := range []string{"bots", "providers", "operator-system"} {
		if err := kube.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name}}); err != nil {
			t.Fatal(err)
		}
	}
	objects := []client.Object{
		&forgev1.ForgejoGPGKey{ObjectMeta: metav1.ObjectMeta{Name: f.key.Name, Namespace: f.key.Namespace}},
		&forgev1.ForgejoProvider{ObjectMeta: metav1.ObjectMeta{Name: "shared", Namespace: "providers"}},
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "admin", Namespace: "providers"}},
	}
	for _, object := range objects {
		if err := f.r.Get(ctx, client.ObjectKeyFromObject(object), object); err != nil {
			t.Fatal(err)
		}
		object.SetResourceVersion("")
		object.SetUID("")
		if err := kube.Create(ctx, object); err != nil {
			t.Fatal(err)
		}
	}
	// Install the actual rendered chart RBAC, then use authenticated clients.
	operatorName := installGPGChartRBAC(t, ctx, kube)
	makeClient := func(name string) client.Client {
		user, err := environment.AddUser(envtest.User{Name: name, Groups: []string{"system:authenticated"}}, config)
		if err != nil {
			t.Fatal(err)
		}
		c, err := client.New(user.Config(), client.Options{Scheme: f.r.Scheme()})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	operator := makeClient("system:serviceaccount:operator-system:" + operatorName)
	tenant := makeClient("gpg-tenant")
	// Even broad ConfigMap/Secret writers in the operator namespace cannot
	// pre-create the cluster-scoped trust root (reflector's old attack surface).
	tenantRole := &rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: "gpg-tenant"}, Rules: []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps", "secrets"}, Verbs: []string{"*"}}}}
	if err := kube.Create(ctx, tenantRole); err != nil {
		t.Fatal(err)
	}
	if err := kube.Create(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "gpg-tenant"}, RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: tenantRole.Name}, Subjects: []rbacv1.Subject{{Kind: "User", Name: "gpg-tenant", APIGroup: rbacv1.GroupName}}}); err != nil {
		t.Fatal(err)
	}
	var source forgev1.ForgejoGPGKey
	if err := kube.Get(ctx, f.key, &source); err != nil {
		t.Fatal(err)
	}
	stateRef, _ := f.r.journalKey(&source)
	forgedState := &forgev1.ForgejoGPGKeyState{ObjectMeta: metav1.ObjectMeta{Name: stateRef.Name, Annotations: map[string]string{gpgSourceUID: string(source.UID), gpgSourceName: source.Name, gpgSourceNamespace: source.Namespace}}, Spec: forgev1.GPGKeyStateSpec{Minted: map[string]string{"ATTACKER": "FORGED"}, CurrentID: "ATTACKER"}}
	if err := tenant.Create(ctx, forgedState); !apierrors.IsForbidden(err) {
		t.Fatalf("tenant could pre-create trust root: %v", err)
	}
	if err := tenant.Create(ctx, &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: stateRef.Name, Namespace: "operator-system", Annotations: map[string]string{"reflector.v1.k8s.emberstack.com/reflects": "bots/forged"}}, Data: map[string]string{"journal": `{"minted":{"ATTACKER":"FORGED"},"currentID":"ATTACKER"}`}}); err != nil {
		t.Fatalf("tenant ConfigMap fixture failed: %v", err)
	}
	f.r.Client = operator
	key := f.reconcile()
	if key.Spec.Algorithm != "ed25519" {
		t.Fatal("algorithm default was not applied")
	}
	if key.Status.KeyID == "" {
		t.Fatalf("operator failed under chart RBAC: %+v", key.Status.Conditions)
	}
	var protected forgev1.ForgejoGPGKeyState
	if err := kube.Get(ctx, stateRef, &protected); err != nil {
		t.Fatal(err)
	}
	protected.Spec.CurrentID = "ATTACKER"
	if err := tenant.Update(ctx, &protected); !apierrors.IsForbidden(err) {
		t.Fatalf("tenant state update allowed: %v", err)
	}
	if err := tenant.Patch(ctx, &protected, client.RawPatch(types.MergePatchType, []byte(`{"spec":{"currentID":"ATTACKER"}}`))); !apierrors.IsForbidden(err) {
		t.Fatalf("tenant state patch allowed: %v", err)
	}
	if err := tenant.Delete(ctx, &protected); !apierrors.IsForbidden(err) {
		t.Fatalf("tenant state delete allowed: %v", err)
	}
	first := key.Status.KeyID
	key = f.reconcile()
	if f.posts != 1 {
		t.Fatal("status/Secret persistence duplicated registration")
	}
	key.Spec.User = "different-account"
	if err := kube.Update(ctx, key); !apierrors.IsInvalid(err) {
		t.Fatalf("user mutation was not rejected: %v", err)
	}
	f.rotation()
	f.now = f.now.Add(2 * time.Hour)
	if f.reconcile().Status.KeyID == first {
		t.Fatal("rotation failed against real Kubernetes")
	}
	if err := kube.Get(ctx, f.key, &source); err != nil {
		t.Fatal(err)
	}
	if err := kube.Delete(ctx, &source); err != nil {
		t.Fatal(err)
	}
	if _, err := f.r.Reconcile(ctx, ctrl.Request{NamespacedName: f.key}); err != nil {
		t.Fatal(err)
	}
	if err := kube.Get(ctx, stateRef, &forgev1.ForgejoGPGKeyState{}); !apierrors.IsNotFound(err) {
		t.Fatalf("operator failed to delete state under chart RBAC: %v", err)
	}
	if err := kube.Get(ctx, f.key, &forgev1.ForgejoGPGKey{}); !apierrors.IsNotFound(err) {
		t.Fatalf("state cleanup finalizer retained: %v", err)
	}
}

// Check the rendered chart itself, not a hand-written approximation of its RBAC.
func installGPGChartRBAC(t *testing.T, ctx context.Context, kube client.Client) string {
	t.Helper()
	output, err := exec.Command("helm", "template", "test", "../../charts/forgejo-operator", "--namespace", "operator-system").Output()
	if err != nil {
		t.Fatalf("render chart RBAC: %v", err)
	}
	decoder := k8syaml.NewYAMLOrJSONDecoder(bytes.NewReader(output), 4096)
	operatorName := ""
	for {
		var raw runtime.RawExtension
		if err := decoder.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		var object unstructured.Unstructured
		if err := json.Unmarshal(raw.Raw, &object); err != nil {
			t.Fatal(err)
		}
		switch object.GetKind() {
		case "ClusterRole":
			for label := range object.GetLabels() {
				if strings.HasPrefix(label, "rbac.authorization.k8s.io/aggregate-to-") {
					t.Fatalf("aggregated trust-root role: %s", object.GetName())
				}
			}
			if err := kube.Create(ctx, &object); err != nil {
				t.Fatal(err)
			}
		case "ClusterRoleBinding":
			if err := kube.Create(ctx, &object); err != nil {
				t.Fatal(err)
			}
			if strings.HasSuffix(object.GetName(), "-gpg-state") {
				var binding rbacv1.ClusterRoleBinding
				if err := json.Unmarshal(raw.Raw, &binding); err != nil {
					t.Fatal(err)
				}
				if len(binding.Subjects) != 1 || binding.Subjects[0].Kind != "ServiceAccount" || binding.Subjects[0].Namespace != "operator-system" {
					t.Fatal("state role must bind only the operator SA")
				}
				operatorName = binding.Subjects[0].Name
			}
		}
	}
	if operatorName == "" {
		t.Fatal("missing dedicated GPG state binding")
	}
	return operatorName
}
