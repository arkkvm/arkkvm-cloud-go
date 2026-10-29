package service

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// Signer loads the PKCS12 keystore (same file as the legacy MessageSignature)
// and provides:
//   - Sign: SHA256withRSA over the release hash (RSASSA-PKCS1-v1_5, a
//     deterministic signature that must match the Java output byte-for-byte);
//   - DecryptDeviceID: RSA-OAEP(SHA-256 + MGF1-SHA256) with base64url input,
//     used to decrypt the deviceId submitted to GET /releases (deployed branch).
type Signer struct {
	privateKey *rsa.PrivateKey
}

func NewSigner(keystorePath, password string) (*Signer, error) {
	data, err := os.ReadFile(keystorePath)
	if err != nil {
		return nil, fmt.Errorf("read keystore %s: %w", keystorePath, err)
	}
	// pkcs12.Decode returns (privateKey, certificate, err).
	priv, _, err := pkcs12.Decode(data, password)
	if err != nil {
		return nil, fmt.Errorf("decode keystore %s: %w", keystorePath, err)
	}
	rsaKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("keystore %s: private key is not RSA", keystorePath)
	}
	return &Signer{privateKey: rsaKey}, nil
}

// Sign returns base64(SHA256withRSA(message)) — identical output to the Java
// Signature.getInstance("SHA256withRSA") path.
func (s *Signer) Sign(message string) (string, error) {
	digest := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// DecryptDeviceID decrypts a base64url-encoded RSA-OAEP(SHA-256/MGF1-SHA256)
// ciphertext produced by the device firmware. Callers treat any error as
// "fall back to the raw value" (deployed-branch behavior).
func (s *Signer) DecryptDeviceID(cipherText string) (string, error) {
	// The firmware sends unpadded base64url (342 chars for a 256-byte RSA
	// ciphertext); Java's Base64.getUrlDecoder() accepts that, so strip any
	// optional padding and decode with the raw alphabet to match.
	cipherBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(cipherText, "="))
	if err != nil {
		return "", err
	}
	plain, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, s.privateKey, cipherBytes, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
