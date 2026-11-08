package controller

import (
	"testing"
	"time"

	forgev1 "github.com/jakeschurch/forgejo-operator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/event"
)

func TestPrimaryResourceChangesIgnoreStatusOnlyUpdates(t *testing.T) {
	previous := &forgev1.ForgejoRepository{ObjectMeta: metav1.ObjectMeta{Name: "repository", Generation: 1, ResourceVersion: "1"}}
	current := previous.DeepCopy()
	current.ResourceVersion = "2"
	setStatus(&current.Status, current.Generation, nil)
	if primaryResourceChanges().Update(event.UpdateEvent{ObjectOld: previous, ObjectNew: current}) {
		t.Fatal("a status write must not immediately enqueue another remote reconciliation")
	}
}

func TestPrimaryResourceChangesPreserveDesiredStateAndLifecycleUpdates(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*forgev1.ForgejoRepository)
	}{
		{name: "spec generation", change: func(object *forgev1.ForgejoRepository) { object.Generation++ }},
		{name: "annotation", change: func(object *forgev1.ForgejoRepository) {
			object.Annotations = map[string]string{"operator.example/refresh": "1"}
		}},
		{name: "label", change: func(object *forgev1.ForgejoRepository) { object.Labels = map[string]string{"owner": "new"} }},
		{name: "finalizer", change: func(object *forgev1.ForgejoRepository) { object.Finalizers = []string{finalizer} }},
		{name: "deletion", change: func(object *forgev1.ForgejoRepository) {
			stamp := metav1.NewTime(time.Unix(1, 0))
			object.DeletionTimestamp = &stamp
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			previous := &forgev1.ForgejoRepository{ObjectMeta: metav1.ObjectMeta{Name: "repository", Generation: 1}}
			current := previous.DeepCopy()
			test.change(current)
			if !primaryResourceChanges().Update(event.UpdateEvent{ObjectOld: previous, ObjectNew: current}) {
				t.Fatal("desired state and deletion changes must still reconcile immediately")
			}
		})
	}
	filter := primaryResourceChanges()
	if !filter.Create(event.CreateEvent{}) || !filter.Delete(event.DeleteEvent{}) || !filter.Generic(event.GenericEvent{}) {
		t.Fatal("initial resources, deletions and explicit reconciliation events must remain enabled")
	}
}
