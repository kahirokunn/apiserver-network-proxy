package util

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/credentials"
)

func TestReloadingClientTLSCredentialsRotatesCertificateAndCA(t *testing.T) {
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	certFile := filepath.Join(dir, "tls.crt")
	keyFile := filepath.Join(dir, "tls.key")

	firstCA := newTestCA(t, "first-ca")
	firstServerCert, firstServerKey := firstCA.issue(t, "proxy.test", true)
	firstClientCert, firstClientKey := firstCA.issue(t, "client-one", false)
	writeTLSFiles(t, caFile, certFile, keyFile, firstCA.pem, firstClientCert, firstClientKey)

	reloading, err := GetReloadingClientTLSCredentials(caFile, certFile, keyFile, "proxy.test", []string{"h2"})
	if err != nil {
		t.Fatal(err)
	}
	directConfig, err := GetClientTLSConfig(caFile, certFile, keyFile, "proxy.test", []string{"h2"})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := clientCertificateCommonName(t, reloading, firstCA.serverConfig(t, firstServerCert, firstServerKey)); err != nil || got != "client-one" {
		t.Fatalf("initial handshake client = %q, err=%v", got, err)
	}

	secondClientCert, secondClientKey := firstCA.issue(t, "client-two", false)
	writeTLSFiles(t, caFile, certFile, keyFile, firstCA.pem, secondClientCert, secondClientKey)
	rotatedCertificate, err := directConfig.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatal(err)
	}
	rotatedLeaf, err := x509.ParseCertificate(rotatedCertificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if rotatedLeaf.Subject.CommonName != "client-two" {
		t.Fatalf("direct TLS config reloaded client CN %q, want client-two", rotatedLeaf.Subject.CommonName)
	}
	if got, err := clientCertificateCommonName(t, reloading, firstCA.serverConfig(t, firstServerCert, firstServerKey)); err != nil || got != "client-two" {
		t.Fatalf("client certificate rotation = %q, err=%v", got, err)
	}

	secondCA := newTestCA(t, "second-ca")
	secondServerCert, secondServerKey := secondCA.issue(t, "proxy.test", true)
	thirdClientCert, thirdClientKey := secondCA.issue(t, "client-three", false)
	writeTLSFiles(t, caFile, certFile, keyFile, secondCA.pem, thirdClientCert, thirdClientKey)
	if got, err := clientCertificateCommonName(t, reloading, secondCA.serverConfig(t, secondServerCert, secondServerKey)); err != nil || got != "client-three" {
		t.Fatalf("CA rotation = %q, err=%v", got, err)
	}

	if err := os.WriteFile(certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := clientCertificateCommonName(t, reloading, secondCA.serverConfig(t, secondServerCert, secondServerKey)); err == nil {
		t.Fatal("malformed rotated certificate unexpectedly completed a handshake")
	}
	writeTLSFiles(t, caFile, certFile, keyFile, secondCA.pem, thirdClientCert, thirdClientKey)
	if got, err := clientCertificateCommonName(t, reloading, secondCA.serverConfig(t, secondServerCert, secondServerKey)); err != nil || got != "client-three" {
		t.Fatalf("handshake did not recover after repairing projected files: client=%q err=%v", got, err)
	}
}

func clientCertificateCommonName(t *testing.T, clientCredentials credentials.TransportCredentials, serverConfig *tls.Config) (string, error) {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	type serverResult struct {
		commonName string
		err        error
	}
	serverDone := make(chan serverResult, 1)
	go func() {
		server := tls.Server(serverRaw, serverConfig)
		defer server.Close()
		if err := server.Handshake(); err != nil {
			serverDone <- serverResult{err: err}
			return
		}
		serverDone <- serverResult{commonName: server.ConnectionState().PeerCertificates[0].Subject.CommonName}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, clientErr := clientCredentials.ClientHandshake(ctx, "proxy.test", clientRaw)
	result := <-serverDone
	_ = clientRaw.Close()
	if clientErr != nil {
		return "", clientErr
	}
	return result.commonName, result.err
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
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: commonName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCA{certificate: certificate, privateKey: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func (ca testCA) issue(t *testing.T, commonName string, server bool) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	extendedUsage := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	dnsNames := []string(nil)
	if server {
		extendedUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		dnsNames = []string{"proxy.test"}
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: extendedUsage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.privateKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func (ca testCA) serverConfig(t *testing.T, certPEM, keyPEM []byte) *tls.Config {
	t.Helper()
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(ca.pem) {
		t.Fatal("append test client CA")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs, NextProtos: []string{"h2"},
	}
}

func writeTLSFiles(t *testing.T, caFile, certFile, keyFile string, caPEM, certPEM, keyPEM []byte) {
	t.Helper()
	for path, data := range map[string][]byte{caFile: caPEM, certFile: certPEM, keyFile: keyPEM} {
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
