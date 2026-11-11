package controller

import (
	"context"
	"os"
	"testing"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	kube, err := client.New(config, client.Options{Scheme: f.r.Scheme()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, name := range []string{"bots", "providers"} {
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
	f.r.Client = kube
	key := f.reconcile()
	if key.Spec.Algorithm != "ed25519" {
		t.Fatal("algorithm default was not applied")
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
}
