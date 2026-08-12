/*
Copyright 2026 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	certutil "k8s.io/client-go/util/cert"
)

func TestNewCACertPoolRejectsPartiallyInvalidBundle(t *testing.T) {
	ca := newTestCA(t, "ca")
	nonCertificateBlock := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not a private key")})

	tests := []struct {
		name    string
		bundle  []byte
		wantErr bool
	}{
		{name: "non-certificate block is ignored", bundle: append(append([]byte(nil), ca.pem...), nonCertificateBlock...)},
		{name: "malformed certificate block is rejected", bundle: append(append([]byte(nil), ca.pem...), malformedCertificatePEM()...), wantErr: true},
		// The two cases below document the boundary of the guarantee: data
		// that does not form a valid PEM block is skipped by the parser
		// rather than rejected, the same behavior as kube-apiserver's
		// dynamic CA reload.
		{name: "truncated trailing block is skipped", bundle: append(append([]byte(nil), ca.pem...), []byte("-----BEGIN CERTIFICATE-----\nMIIBtruncated\n")...)},
		{name: "block with corrupted base64 is skipped", bundle: append(append([]byte(nil), ca.pem...), []byte("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n")...)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool, err := newCACertPool(tt.bundle)
			if tt.wantErr {
				if err == nil {
					t.Fatal("CA bundle unexpectedly loaded")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if pool == nil {
				t.Fatal("CA bundle returned a nil pool")
			}
		})
	}
}

func TestGetClientTLSConfigRejectsPartiallyInvalidCABundle(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	ca := newTestCA(t, "ca")
	bundle := append(append([]byte(nil), ca.pem...), malformedCertificatePEM()...)
	if err := os.WriteFile(caFile, bundle, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := GetClientTLSConfig(caFile, "", "", "proxy.test", nil)
	if err == nil {
		t.Fatal("partially invalid CA bundle unexpectedly loaded")
	}
	if !strings.Contains(err.Error(), caFile) {
		t.Fatalf("error %q does not identify the CA file %q", err, caFile)
	}
}

type testCA struct {
	certificate *x509.Certificate
	privateKey  *ecdsa.PrivateKey
	pem         []byte
}

func newTestCA(t *testing.T, commonName string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := certutil.NewSelfSignedCACert(certutil.Config{CommonName: commonName}, key)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{
		certificate: certificate,
		privateKey:  key,
		pem:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}),
	}
}

func malformedCertificatePEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a DER-encoded certificate")})
}
