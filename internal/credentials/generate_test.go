package credentials

import (
	"bytes"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestStableAndRotatingSecret(t *testing.T) {
	owner := metav1.OwnerReference{APIVersion: "v1", Kind: "Example", Name: "owner"}
	first, changed, err := StableSecret(nil, "ns", "generated", "token", "one", owner)
	if err != nil || !changed {
		t.Fatalf("first: changed=%v err=%v", changed, err)
	}
	second, changed, err := StableSecret(first, "ns", "generated", "token", "one", owner)
	if err != nil || changed || !bytes.Equal(first.Data["token"], second.Data["token"]) {
		t.Fatal("stable secret rotated")
	}
	third, changed, err := StableSecret(second, "ns", "generated", "token", "two", owner)
	if err != nil || !changed || bytes.Equal(second.Data["token"], third.Data["token"]) {
		t.Fatal("rotation nonce did not rotate")
	}
}
