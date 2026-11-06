package state

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"os"
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
// Comments are STRIPPED from the sealed plaintext: the operator's raw
// central.yaml keeps its documentation (the daemon preserves the comments
// of the local file it refreshes — see MarshalPreservingComments), while the
// distributed central.nybundle is clean config. The comment lifecycle is
// therefore: raw central.yaml (comments live here, forever) → seal strips →
// bundle (clean) → poll → the daemon's local cache (whatever the local file
// already carried).
func BundleConfig(config string, rootKey NyPrivateKey) (string, error) {
	cfg := CentralCfg{}
	// Strict: a key CentralCfg does not model must fail the seal loudly, not
	// silently vanish from the distributed bundle — a dropped section (e.g.
	// priority_rules at an unsupported level) is indistinguishable from
	// "applied" until traffic proves otherwise.
	err := yaml.UnmarshalWithOptions([]byte(config), &cfg, yaml.Strict())
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

	plainText, err := yaml.Marshal(cfg)
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
// config and the sealed plaintext — the exact YAML the seal produced (clean
// of comments; the operator's documentation lives in the raw central.yaml,
// which the seal strips and the daemon's local cache preserves — see
// MarshalPreservingComments). `nylon open` prints the plaintext so an
// audited bundle reads like the config the nodes will run; nodes on the
// poll path use UnbundleConfig and never need the text.
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

// MarshalPreservingComments renders cfg as YAML carrying over the comments
// of the file at existingPath (when it exists and parses): the daemon
// refreshes its local central.yaml cache on every applied config update,
// and the file it overwrites may be the operator's hand-written, documented
// central.yaml — the values change, the documentation must not. Comments
// map by YAML path, so comments of paths that still exist reattach; a
// removed section's comments drop with it. When the existing file cannot be
// read or parsed (absent, unreadable, stale), the result is a plain
// comment-free marshal — a machine-written cache carries no comments anyway.
func MarshalPreservingComments(cfg *CentralCfg, existingPath string) []byte {
	plain, err := yaml.Marshal(cfg)
	if err != nil {
		return nil
	}
	file, err := os.ReadFile(existingPath)
	if err != nil {
		return plain
	}
	// non-strict on purpose: the existing file may carry keys this binary no
	// longer models (a stale cache being replaced by a fresh fetch); the
	// comments of the paths that still match are what we keep.
	comments := yaml.CommentMap{}
	throwaway := CentralCfg{}
	if err := yaml.UnmarshalWithOptions(file, &throwaway, yaml.CommentToMap(comments)); err != nil {
		return plain
	}
	if len(comments) == 0 {
		return plain
	}
	out, err := yaml.MarshalWithOptions(cfg, yaml.WithComment(comments))
	if err != nil {
		return plain
	}
	return out
}
