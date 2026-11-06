package state

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"time"

	"github.com/goccy/go-yaml"
	"go.step.sm/crypto/x25519"
	"golang.org/x/crypto/chacha20poly1305"
)

func SignBundle(data []byte, key NyPrivateKey) ([]byte, error) {
	privKey := x25519.PrivateKey(key[:])
	sig, err := privKey.Sign(rand.Reader, data, crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	return append(sig, data...), nil
}

func VerifyBundle(data []byte, key NyPublicKey) ([]byte, error) {
	if len(data) < x25519.SignatureSize {
		return nil, errors.New("invalid signature: too short")
	}
	signature := data[:x25519.SignatureSize]
	plainText := data[x25519.SignatureSize:]
	if !x25519.Verify(key[:], plainText, signature) {
		return nil, errors.New("invalid signature")
	}
	return plainText, nil
}

func SealBundle(data []byte, key []byte) ([]byte, error) {
	ahead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}
	cipherText := ahead.Seal(make([]byte, 0), nonce, data, make([]byte, 0))
	return append(nonce, cipherText...), nil
}

func OpenBundle(data []byte, key []byte) ([]byte, error) {
	if len(data) < chacha20poly1305.NonceSizeX {
		return nil, errors.New("invalid bundle, too small")
	}
	ahead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, err
	}
	nonce := data[:chacha20poly1305.NonceSizeX]
	cipherText := data[chacha20poly1305.NonceSizeX:]
	bundle, err := ahead.Open(make([]byte, 0), nonce, cipherText, make([]byte, 0))
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

// BundleConfig first signs the config with the root private key, ensuring the authenticity, then encrypts the message using the bytes of the root public key as the shared key, offering some level of privacy. (assuming the root public key is not shared widely)
//
// Comments survive the seal: the comments of the hand-written central.yaml are
// captured during the strict decode (yaml.CommentToMap) and reattached to the
// sealed plaintext at marshal time (yaml.WithComment), so `nylon open` shows
// the bundle exactly as the operator documented it. Comment positions map by
// path; the seal only mutates `timestamp`, which keeps its path, so every
// captured comment reattaches.
func BundleConfig(config string, rootKey NyPrivateKey) (string, error) {
	cfg := CentralCfg{}
	comments := yaml.CommentMap{}
	// Strict: a key CentralCfg does not model must fail the seal loudly, not
	// silently vanish from the distributed bundle — a dropped section (e.g.
	// priority_rules at an unsupported level) is indistinguishable from
	// "applied" until traffic proves otherwise.
	err := yaml.UnmarshalWithOptions([]byte(config), &cfg, yaml.Strict(), yaml.CommentToMap(comments))
	if err != nil {
		return "", err
	}
	err = CentralConfigValidator(&cfg)
	if err != nil {
		return "", err
	}
	if cfg.Dist != nil && cfg.Dist.Key != rootKey.Pubkey() {
		slog.Warn("bundled public key differs from the signing key, check if this is intended!")
	}
	cfg.Timestamp = time.Now().UnixNano()

	plainText, err := yaml.MarshalWithOptions(cfg, yaml.WithComment(comments))
	if err != nil {
		return "", err
	}

	bundle, err := SignBundle(plainText, rootKey)
	if err != nil {
		return "", err
	}
	pub := rootKey.Pubkey()
	bundle, err = SealBundle(bundle, pub[:])
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(bundle), nil
}

// UnbundleConfigText verifies and opens a bundle and returns both the parsed
// config and the sealed plaintext — the exact YAML the seal produced, comments
// included. `nylon open` prints the plaintext so an audited bundle reads like
// the operator's central.yaml; nodes on the poll path use UnbundleConfig and
// never need the text.
func UnbundleConfigText(bundleStr string, pubKey NyPublicKey) (string, *CentralCfg, error) {
	bundle, err := base64.StdEncoding.DecodeString(bundleStr)
	if err != nil {
		return "", nil, err
	}
	bundle, err = OpenBundle(bundle, pubKey[:])
	if err != nil {
		return "", nil, err
	}
	bundle, err = VerifyBundle(bundle, pubKey)
	if err != nil {
		return "", nil, err
	}

	cfg := &CentralCfg{}
	// Strict: a bundle carrying a field this binary does not know fails the
	// poll loudly and the node keeps its last active config
	// (core.checkForConfigUpdates), instead of half-applying a newer central
	// config whose unknown section would silently drop.
	err = yaml.UnmarshalWithOptions(bundle, cfg, yaml.Strict())
	if err != nil {
		return "", nil, err
	}
	err = CentralConfigValidator(cfg)
	if err != nil {
		return "", nil, err
	}
	return string(bundle), cfg, nil
}

func UnbundleConfig(bundleStr string, pubKey NyPublicKey) (*CentralCfg, error) {
	_, cfg, err := UnbundleConfigText(bundleStr, pubKey)
	return cfg, err
}
