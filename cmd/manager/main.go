package main

import (
	"crypto/tls"
	"flag"
	"os"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	"github.com/jakeschurch/forgejo-operator/internal/controller"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
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
	})
	if err != nil {
		os.Exit(1)
	}
	base := controller.Reconciler{Client: manager.GetClient()}
	for _, setup := range []func(ctrl.Manager) error{
		(&controller.ProviderReconciler{Reconciler: base}).SetupWithManager,
		(&controller.OrganizationReconciler{Reconciler: base}).SetupWithManager,
		(&controller.RepositoryReconciler{Reconciler: base}).SetupWithManager,
	} {
		if err := setup(manager); err != nil {
			os.Exit(1)
		}
	}
	if manager.AddHealthzCheck("healthz", healthz.Ping) != nil || manager.AddReadyzCheck("readyz", healthz.Ping) != nil {
		os.Exit(1)
	}
	if err := manager.Start(ctrl.SetupSignalHandler()); err != nil {
		os.Exit(1)
	}
}
