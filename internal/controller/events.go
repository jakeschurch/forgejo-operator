package controller

import (
	"reflect"

	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
)

// Status writes carry a reconciliation timestamp, so observing them would
// bypass RequeueAfter and continuously reconcile otherwise unchanged resources.
// Keep metadata and deletion events: generation alone does not cover finalizers.
func primaryResourceChanges() predicate.Predicate {
	return predicate.Funcs{UpdateFunc: func(update event.UpdateEvent) bool {
		previous, current := update.ObjectOld, update.ObjectNew
		if previous == nil || current == nil {
			return false
		}
		return previous.GetGeneration() != current.GetGeneration() ||
			!reflect.DeepEqual(previous.GetAnnotations(), current.GetAnnotations()) ||
			!reflect.DeepEqual(previous.GetLabels(), current.GetLabels()) ||
			!reflect.DeepEqual(previous.GetFinalizers(), current.GetFinalizers()) ||
			!previous.GetDeletionTimestamp().Equal(current.GetDeletionTimestamp())
	}}
}
