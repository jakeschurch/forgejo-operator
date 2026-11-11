package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	"github.com/jakeschurch/forgejo-operator/internal/controller"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	"sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func main() {
	var metricsAddress, probeAddress string
	var leaderElection, secureMetrics bool
	flag.StringVar(&metricsAddress, "metrics-bind-address", ":8443", "metrics endpoint address")
	flag.StringVar(&probeAddress, "health-probe-bind-address", ":8081", "probe endpoint address")
	flag.BoolVar(&leaderElection, "leader-elect", true, "enable leader election")
	flag.BoolVar(&secureMetrics, "metrics-secure", true, "serve metrics with authentication and authorization")
	flag.Parse()

	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(forgev1.AddToScheme(scheme))
	metrics := server.Options{BindAddress: metricsAddress, SecureServing: secureMetrics, TLSOpts: []func(*tls.Config){func(c *tls.Config) { c.MinVersion = tls.VersionTLS12 }}}
	if secureMetrics {
		metrics.FilterProvider = filters.WithAuthenticationAndAuthorization
	}
	manager, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme, Metrics: metrics, HealthProbeBindAddress: probeAddress,
		LeaderElection: leaderElection, LeaderElectionID: "forgejo-operator.forgejo.jakeschurch.com",
		// 2026-11-11: warm standby sources before readiness can allow retirement
		// of the old leader; release the lease after manager shutdown completes.
		Controller:                    config.Controller{EnableWarmup: ptr.To(true)},
		LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		os.Exit(1)
	}
	base := controller.Reconciler{Client: manager.GetClient()}
	setups := []func(ctrl.Manager) error{
		(&controller.ProviderReconciler{Reconciler: base}).SetupWithManager,
		(&controller.OrganizationReconciler{Reconciler: base}).SetupWithManager,
		(&controller.RepositoryReconciler{Reconciler: base}).SetupWithManager,
	}
	if namespace := os.Getenv("POD_NAMESPACE"); namespace != "" {
		setups = append(setups, (&controller.GPGKeyReconciler{Reconciler: base, StateNamespace: namespace}).SetupWithManager)
	} else {
		log.Print("GPG controller disabled: POD_NAMESPACE is empty")
	}
	setups = append(setups, controller.ManagedSetups(base)...)
	for _, setup := range setups {
		if err := setup(manager); err != nil {
			os.Exit(1)
		}
	}
	// 2026-11-11: readiness includes cache initialization and shutdown, including
	// healthy election standbys; liveness must survive remote dependency outages.
	ctx := ctrl.SetupSignalHandler()
	ready := cacheReady(ctx, manager.GetCache())
	if manager.AddHealthzCheck("healthz", healthz.Ping) != nil || manager.AddReadyzCheck("readyz", ready) != nil {
		os.Exit(1)
	}
	if err := manager.Start(ctx); err != nil {
		os.Exit(1)
	}
}

// cacheSyncer lets readiness be checked without running a Kubernetes manager.
type cacheSyncer interface {
	WaitForCacheSync(context.Context) bool
}

func cacheReady(ctx context.Context, cache cacheSyncer) healthz.Checker {
	return func(request *http.Request) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Leave time for the error response within the kubelet's 1s timeout.
		probeCtx, cancel := context.WithTimeout(request.Context(), 500*time.Millisecond)
		defer cancel()
		if !cache.WaitForCacheSync(probeCtx) {
			return fmt.Errorf("cache not synchronized")
		}
		return ctx.Err()
	}
}
