package credentials

import (
	"bytes"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

func TestGPGAlgorithmsAndIdentity(t *testing.T) {
	for _, algorithm := range []string{"ed25519", "rsa4096"} {
		t.Run(algorithm, func(t *testing.T) {
			key, err := GenerateGPG("Renovate", "renovate@example.test", algorithm, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(key.Private))
			if err != nil {
				t.Fatal(err)
			}
			entity := entities[0]
			if len(entity.Subkeys) != 1 {
				t.Fatal("missing encryption subkey")
			}
			if algorithm == "ed25519" {
				if entity.PrimaryKey.PubKeyAlgo != packet.PubKeyAlgoEdDSA || entity.Subkeys[0].PublicKey.PubKeyAlgo != packet.PubKeyAlgoECDH {
					t.Fatal("incorrect ed25519/cv25519 algorithm pair")
				}
				curve, err := entity.Subkeys[0].PublicKey.Curve()
				if err != nil || curve != packet.Curve25519 {
					t.Fatal("incorrect encryption curve")
				}
			} else {
				bits, err := entity.PrimaryKey.BitLength()
				if err != nil || bits != 4096 || entity.PrimaryKey.PubKeyAlgo != packet.PubKeyAlgoRSA {
					t.Fatal("incorrect RSA parameters")
				}
			}
			if _, err := ReadGPG(key.Private, "Someone Else", "renovate@example.test", algorithm); err == nil {
				t.Fatal("mismatched identity accepted")
			}
		})
	}
}
