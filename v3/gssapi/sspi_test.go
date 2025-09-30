//go:build windows
// +build windows

package gssapi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// createTestCertificate creates a test certificate with the specified signature algorithm.
func createTestCertificate(sigAlg x509.SignatureAlgorithm) (*x509.Certificate, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SignatureAlgorithm: sigAlg,
		SerialNumber:       big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Company"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func TestNewSSPIClientWithChannelBinding(t *testing.T) {
	tests := []struct {
		name   string
		sigAlg x509.SignatureAlgorithm
	}{
		{
			name:   x509.SHA256WithRSA.String(),
			sigAlg: x509.SHA256WithRSA,
		},
		{
			name:   x509.SHA384WithRSA.String(),
			sigAlg: x509.SHA384WithRSA,
		},
		{
			name:   x509.SHA512WithRSA.String(),
			sigAlg: x509.SHA512WithRSA,
		},
		{
			name:   x509.SHA1WithRSA.String() + " (should fallback to SHA256)",
			sigAlg: x509.SHA1WithRSA,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert, err := createTestCertificate(tt.sigAlg)
			if err != nil {
				t.Fatalf("Failed to create test certificate: %v", err)
			}

			client, err := NewSSPIClientWithChannelBinding(cert)
			t.Cleanup(func() {
				client.Close()
			})

			if err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			if client == nil {
				t.Error("Expected client but got nil")
			}
			if len(client.channelBindings) == 0 {
				t.Error("Expected channel bindings to be set")
			}

			applicationData := client.channelBindings[32:]
			expectedPrefix := "tls-server-end-point:"
			if !strings.HasPrefix(string(applicationData), expectedPrefix) {
				t.Errorf("Expected application data to start with %q, got %q", expectedPrefix, string(applicationData))
			}
		})
	}
}
