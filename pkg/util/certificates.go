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
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"google.golang.org/grpc/credentials"
)

// getCACertPool loads CA certificates to pool
func getCACertPool(caFile string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	caCert, err := os.ReadFile(filepath.Clean(caFile))
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert %s: %v", caFile, err)
	}
	ok := certPool.AppendCertsFromPEM(caCert)
	if !ok {
		return nil, fmt.Errorf("failed to append CA cert to the cert pool")
	}
	return certPool, nil
}

// GetClientTLSConfig returns tlsConfig based on x509 certs
func GetClientTLSConfig(caFile, certFile, keyFile, serverName string, protos []string) (*tls.Config, error) {
	certPool, err := getCACertPool(caFile)
	if err != nil {
		return nil, err
	}

	tlsConfig := &tls.Config{
		RootCAs:    certPool,
		MinVersion: tls.VersionTLS12,
	}
	if len(protos) != 0 {
		tlsConfig.NextProtos = protos
	}
	if certFile == "" && keyFile == "" {
		// return TLS config based on CA only
		return tlsConfig, nil
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load X509 key pair %s and %s: %v", certFile, keyFile, err)
	}

	tlsConfig.ServerName = serverName
	tlsConfig.Certificates = []tls.Certificate{cert}
	return tlsConfig, nil
}

// GetReloadingClientTLSCredentials validates the configured files and returns
// client transport credentials that rebuild the TLS config for every new
// connection, so a reconnect after certificate rotation uses the new material.
func GetReloadingClientTLSCredentials(caFile, certFile, keyFile, serverName string, protos []string) (credentials.TransportCredentials, error) {
	if _, err := GetClientTLSConfig(caFile, certFile, keyFile, serverName, protos); err != nil {
		return nil, err
	}
	return &reloadingClientTLSCredentials{
		caFile:     caFile,
		certFile:   certFile,
		keyFile:    keyFile,
		serverName: serverName,
		protos:     protos,
	}, nil
}

type reloadingClientTLSCredentials struct {
	caFile     string
	certFile   string
	keyFile    string
	serverName string
	protos     []string
}

func (c *reloadingClientTLSCredentials) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	tlsConfig, err := GetClientTLSConfig(c.caFile, c.certFile, c.keyFile, c.serverName, c.protos)
	if err != nil {
		_ = rawConn.Close()
		return nil, nil, err
	}
	return credentials.NewTLS(tlsConfig).ClientHandshake(ctx, authority, rawConn)
}

func (*reloadingClientTLSCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	_ = rawConn.Close()
	return nil, nil, fmt.Errorf("reloading client TLS credentials cannot perform a server handshake")
}

func (c *reloadingClientTLSCredentials) Info() credentials.ProtocolInfo {
	return credentials.ProtocolInfo{SecurityProtocol: "tls", SecurityVersion: "1.2", ServerName: c.serverName}
}

func (c *reloadingClientTLSCredentials) Clone() credentials.TransportCredentials {
	clone := *c
	return &clone
}

func (c *reloadingClientTLSCredentials) OverrideServerName(serverName string) error {
	c.serverName = serverName
	return nil
}
