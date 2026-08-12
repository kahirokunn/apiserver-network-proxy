/*
Copyright 2019 The Kubernetes Authors.

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

package util //nolint:revive

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	certutil "k8s.io/client-go/util/cert"
)

// newCACertPool parses caCert as a bundle of PEM-encoded certificates. A
// CERTIFICATE block that does not parse as a certificate rejects the whole
// bundle instead of being skipped. Data that does not form a valid PEM block
// is ignored by the underlying parser, the same behavior as kube-apiserver's
// dynamic CA reload.
func newCACertPool(caCert []byte) (*x509.CertPool, error) {
	certPool, err := certutil.NewPoolFromBytes(caCert)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate bundle: %w", err)
	}
	return certPool, nil
}

// GetClientTLSConfig returns tlsConfig based on x509 certs.
func GetClientTLSConfig(caFile, certFile, keyFile, serverName string, protos []string) (*tls.Config, error) {
	certPool, err := certutil.NewPool(caFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load CA cert %s: %w", caFile, err)
	}

	tlsConfig := &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}
	if len(protos) != 0 {
		tlsConfig.NextProtos = protos
	}
	if certFile == "" && keyFile == "" {
		// Return TLS config based on CA only.
		return tlsConfig, nil
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair %s and %s: %w", certFile, keyFile, err)
	}

	tlsConfig.ServerName = serverName
	tlsConfig.Certificates = []tls.Certificate{cert}
	return tlsConfig, nil
}
