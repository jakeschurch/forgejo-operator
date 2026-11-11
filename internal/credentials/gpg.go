package credentials

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

type GPGKey struct {
	Private, Public    []byte
	KeyID, Fingerprint string
	CreatedAt          time.Time
}

func GenerateGPG(name, email, algorithm string, now time.Time) (*GPGKey, error) {
	config := &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA, Curve: packet.Curve25519, Time: func() time.Time { return now }}
	if algorithm == "rsa4096" {
		config.Algorithm, config.RSABits = packet.PubKeyAlgoRSA, 4096
	} else if algorithm != "" && algorithm != "ed25519" {
		return nil, errors.New("unsupported GPG algorithm")
	}
	entity, err := openpgp.NewEntity(name, "", email, config)
	if err != nil {
		return nil, errors.New("generate OpenPGP key")
	}
	var private bytes.Buffer
	w, err := armor.Encode(&private, openpgp.PrivateKeyType, nil)
	if err != nil {
		return nil, errors.New("armor OpenPGP private key")
	}
	if err := entity.SerializePrivate(w, config); err != nil {
		return nil, errors.New("serialize OpenPGP private key")
	}
	if err := w.Close(); err != nil {
		return nil, errors.New("close OpenPGP private armor")
	}
	return ReadGPG(private.Bytes(), name, email, algorithm)
}

// ReadGPG derives public metadata from private material. All failures are static:
// parser errors can contain supplied data and must never reach status or logs.
func ReadGPG(private []byte, name, email, algorithm string) (*GPGKey, error) {
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(private))
	if err != nil || len(entities) != 1 {
		return nil, errors.New("Secret must contain one armored OpenPGP private key")
	}
	e := entities[0]
	if e.PrivateKey == nil || e.PrivateKey.Encrypted || len(e.Identities) != 1 || e.Revoked(time.Now()) {
		return nil, errors.New("Secret must contain one unencrypted, unrevoked signing identity")
	}
	for _, id := range e.Identities {
		if id.UserId.Name != name || id.UserId.Email != email {
			return nil, errors.New("OpenPGP identity does not match spec.identity")
		}
	}
	if algorithm == "rsa4096" {
		bits, err := e.PrimaryKey.BitLength()
		if err != nil || e.PrimaryKey.PubKeyAlgo != packet.PubKeyAlgoRSA || bits != 4096 {
			return nil, errors.New("OpenPGP key does not match rsa4096")
		}
	} else {
		curve, err := e.PrimaryKey.Curve()
		if (algorithm != "" && algorithm != "ed25519") || err != nil || curve != packet.Curve25519 || e.PrimaryKey.PubKeyAlgo != packet.PubKeyAlgoEdDSA {
			return nil, errors.New("OpenPGP key does not match ed25519")
		}
	}
	var public bytes.Buffer
	w, err := armor.Encode(&public, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, errors.New("armor OpenPGP public key")
	}
	if err := e.Serialize(w); err != nil {
		return nil, errors.New("serialize OpenPGP public key")
	}
	if err := w.Close(); err != nil {
		return nil, errors.New("close OpenPGP public armor")
	}
	return &GPGKey{Private: private, Public: public.Bytes(), KeyID: e.PrimaryKey.KeyIdString(), Fingerprint: strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint)), CreatedAt: e.PrimaryKey.CreationTime}, nil
}
