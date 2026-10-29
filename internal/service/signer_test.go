package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// newTestSigner builds a Signer from an in-memory generated PKCS12 keystore,
// so DecryptDeviceID can be exercised without the production keystore file.
func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "signer-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pfx, err := pkcs12.Encode(rand.Reader, key, cert, nil, "test-password")
	if err != nil {
		t.Fatalf("encode pkcs12: %v", err)
	}
	path := filepath.Join(t.TempDir(), "test.p12")
	if err := os.WriteFile(path, pfx, 0o600); err != nil {
		t.Fatalf("write keystore: %v", err)
	}
	signer, err := NewSigner(path, "test-password")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer
}

// encryptDeviceID mirrors the firmware: RSA-OAEP(SHA-256/MGF1-SHA256) with
// the signer's public key.
func encryptDeviceID(t *testing.T, s *Signer, plain string) []byte {
	t.Helper()
	cipher, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &s.privateKey.PublicKey, []byte(plain), nil)
	if err != nil {
		t.Fatalf("encrypt device id: %v", err)
	}
	return cipher
}

func TestDecryptDeviceID(t *testing.T) {
	s := newTestSigner(t)
	const sn = "4bee9d1e187d7a2c"
	cipher := encryptDeviceID(t, s, sn)

	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Regression: the device firmware sends unpadded base64url (a
		// 342-char ciphertext for RSA-2048); the strict padded decoder
		// rejected it and silently broke internal/gray distribution.
		{"unpadded base64url (firmware format)", base64.RawURLEncoding.EncodeToString(cipher), false},
		{"padded base64url", base64.URLEncoding.EncodeToString(cipher), false},
		{"invalid base64", "not@valid!", true},
		{"wrong ciphertext size", base64.RawURLEncoding.EncodeToString([]byte("too-short")), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plain, err := s.DecryptDeviceID(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("DecryptDeviceID(%q) succeeded, want error", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecryptDeviceID: %v", err)
			}
			if plain != sn {
				t.Errorf("DecryptDeviceID = %q, want %q", plain, sn)
			}
		})
	}
}
