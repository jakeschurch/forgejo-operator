package credentials

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const RotationNonceAnnotation = "forgejo.jakeschurch.com/rotation-nonce"

func StableSecret(existing *corev1.Secret, namespace, name, key, nonce string, owner metav1.OwnerReference) (*corev1.Secret, bool, error) {
	if existing != nil && existing.Annotations[RotationNonceAnnotation] == nonce && len(existing.Data[key]) > 0 {
		return existing.DeepCopy(), false, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, false, fmt.Errorf("generate credential: %w", err)
	}
	value := base64.RawURLEncoding.EncodeToString(raw)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: namespace,
			Annotations:     map[string]string{RotationNonceAnnotation: nonce},
			OwnerReferences: []metav1.OwnerReference{owner},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{key: []byte(value)},
	}
	return secret, true, nil
}
