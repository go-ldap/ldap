//go:build windows
// +build windows

package gssapi

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/binary"
	"fmt"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/kerberos"
)

// SSPIClient implements ldap.GSSAPIClient interface.
// Depends on secur32.dll.
type SSPIClient struct {
	creds           *sspi.Credentials
	ctx             *kerberos.ClientContext
	channelBindings []byte
}

// NewSSPIClient returns a client with credentials of the current user.
func NewSSPIClient() (*SSPIClient, error) {
	creds, err := kerberos.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}

	return NewSSPIClientWithCredentials(creds), nil
}

// NewSSPIClientWithCredentials returns a client with the provided credentials.
func NewSSPIClientWithCredentials(creds *sspi.Credentials) *SSPIClient {
	return &SSPIClient{
		creds: creds,
	}
}

// NewSSPIClientWithUserCredentials returns a client using the provided user's
// credentials.
func NewSSPIClientWithUserCredentials(domain, username, password string) (*SSPIClient, error) {
	creds, err := kerberos.AcquireUserCredentials(domain, username, password)
	if err != nil {
		return nil, err
	}

	return &SSPIClient{
		creds: creds,
	}, nil
}

// NewSSPIClientWithChannelBinding creates an RFC 5929 compliant client.
func NewSSPIClientWithChannelBinding(cert *x509.Certificate) (*SSPIClient, error) {
	creds, err := kerberos.AcquireCurrentUserCredentials()
	if err != nil {
		return nil, err
	}

	certHash := calculateCertificateHash(cert)
	if certHash == nil {
		return nil, fmt.Errorf("failed to calculate certificate hash")
	}

	tlsChannelBinding := append([]byte("tls-server-end-point:"), certHash...)

	return &SSPIClient{
		creds:           creds,
		channelBindings: createChannelBindingsStructure(tlsChannelBinding),
	}, nil
}

// Close deletes any established secure context and closes the client.
func (c *SSPIClient) Close() error {
	err1 := c.DeleteSecContext()
	err2 := c.creds.Release()
	if err1 != nil {
		return err1
	}
	if err2 != nil {
		return err2
	}
	return nil
}

// DeleteSecContext destroys any established secure context.
func (c *SSPIClient) DeleteSecContext() error {
	return c.ctx.Release()
}

// InitSecContext initiates the establishment of a security context for
// GSS-API between the client and server.
// See RFC 4752 section 3.1.
func (c *SSPIClient) InitSecContext(target string, token []byte) ([]byte, bool, error) {
	return c.InitSecContextWithOptions(target, token, []int{})
}

// InitSecContextWithOptions initiates the establishment of a security context for
// GSS-API between the client and server.
// See RFC 4752 section 3.1.
func (c *SSPIClient) InitSecContextWithOptions(target string, token []byte, APOptions []int) ([]byte, bool, error) {
	sspiFlags := uint32(sspi.ISC_REQ_INTEGRITY | sspi.ISC_REQ_CONFIDENTIALITY | sspi.ISC_REQ_MUTUAL_AUTH)

	switch token {
	case nil:
		// Use channel bindings if available, otherwise fall back to the standard method.
		var ctx *kerberos.ClientContext
		var completed bool
		var output []byte
		var err error

		if len(c.channelBindings) > 0 {
			ctx, completed, output, err = kerberos.NewClientContextWithChannelBindings(c.creds, target, sspiFlags, c.channelBindings)
		} else {
			ctx, completed, output, err = kerberos.NewClientContextWithFlags(c.creds, target, sspiFlags)
		}

		if err != nil {
			return nil, false, err
		}
		c.ctx = ctx

		return output, !completed, nil
	default:
		completed, output, err := c.ctx.Update(token)
		if err != nil {
			return nil, false, err
		}
		if err := c.ctx.VerifyFlags(); err != nil {
			return nil, false, fmt.Errorf("error verifying flags: %v", err)
		}
		return output, !completed, nil
	}
}

// NegotiateSaslAuth performs the last step of the SASL handshake.
// See RFC 4752 section 3.1.
func (c *SSPIClient) NegotiateSaslAuth(token []byte, authzid string) ([]byte, error) {
	// Using SSPI rather than of GSSAPI, relevant documentation of differences here:
	// https://learn.microsoft.com/en-us/windows/win32/secauthn/sspi-kerberos-interoperability-with-gssapi

	// KERB_WRAP_NO_ENCRYPT (SECQOP_WRAP_NO_ENCRYPT) flag indicates Wrap and Unwrap
	// should only sign & verify (not encrypt & decrypt).
	const KERB_WRAP_NO_ENCRYPT = 0x80000001

	// https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-decryptmessage
	flags, inputPayload, err := c.ctx.DecryptMessage(token, 0)
	if err != nil {
		return nil, fmt.Errorf("error decrypting message: %w", err)
	}
	if flags&KERB_WRAP_NO_ENCRYPT == 0 {
		// Encrypted message, this is unexpected.
		return nil, fmt.Errorf("message encrypted")
	}

	// `bytes` describes available security context:
	// 		"the first octet of resulting cleartext as a
	// 		bit-mask specifying the security layers supported by the server and
	// 		the second through fourth octets as the maximum size output_message
	// 		the server is able to receive (in network byte order).  If the
	// 		resulting cleartext is not 4 octets long, the client fails the
	// 		negotiation.  The client verifies that the server maximum buffer is 0
	// 		if the server does not advertise support for any security layer."
	// From https://www.rfc-editor.org/rfc/rfc4752#section-3.1
	if len(inputPayload) != 4 {
		return nil, fmt.Errorf("bad server token")
	}
	if inputPayload[0] == 0x0 && !bytes.Equal(inputPayload, []byte{0x0, 0x0, 0x0, 0x0}) {
		return nil, fmt.Errorf("bad server token")
	}

	// Security layers https://www.rfc-editor.org/rfc/rfc4422#section-3.7
	// https://www.rfc-editor.org/rfc/rfc4752#section-3.3
	// supportNoSecurity := input[0] & 0b00000001
	// supportIntegrity := input[0] & 0b00000010
	// supportPrivacy := input[0] & 0b00000100
	selectedSec := 0 // Disabled
	var maxSecMsgSize uint32
	if selectedSec != 0 {
		maxSecMsgSize, _, _, _, err = c.ctx.Sizes()
		if err != nil {
			return nil, fmt.Errorf("error getting security context max message size: %w", err)
		}
	}

	// https://learn.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-encryptmessage
	inputPayload, err = c.ctx.EncryptMessage(handshakePayload(byte(selectedSec), maxSecMsgSize, []byte(authzid)), KERB_WRAP_NO_ENCRYPT, 0)
	if err != nil {
		return nil, fmt.Errorf("error encrypting message: %w", err)
	}

	return inputPayload, nil
}

func handshakePayload(secLayer byte, maxSize uint32, authzid []byte) []byte {
	// construct payload and send unencrypted:
	// 		"The client then constructs data, with the first octet containing the
	// 		bit-mask specifying the selected security layer, the second through
	// 		fourth octets containing in network byte order the maximum size
	// 		output_message the client is able to receive (which MUST be 0 if the
	// 		client does not support any security layer), and the remaining octets
	// 		containing the UTF-8 [UTF8] encoded authorization identity.
	// 		(Implementation note: The authorization identity is not terminated
	// 		with the zero-valued (%x00) octet (e.g., the UTF-8 encoding of the
	// 		NUL (U+0000) character)).  The client passes the data to GSS_Wrap
	// 		with conf_flag set to FALSE and responds with the generated
	// 		output_message.  The client can then consider the server
	// 		authenticated."
	// From https://www.rfc-editor.org/rfc/rfc4752#section-3.1

	// Client picks security layer to use, 0 is disabled.
	var selectedSecurity byte = secLayer
	var truncatedSize uint32 // must be 0 if secLayer is 0
	if selectedSecurity != 0 {
		// Only 3 bytes to describe the max size, set the maximum.
		truncatedSize = 0b00000000_11111111_11111111_11111111
		if truncatedSize > maxSize {
			truncatedSize = maxSize
		}
	}

	payload := make([]byte, 4, 4+len(authzid))
	binary.BigEndian.PutUint32(payload, truncatedSize)
	payload[0] = selectedSecurity // Overwrites most significant byte of `maxSize`
	payload = append(payload, []byte(authzid)...)

	return payload
}

// createChannelBindingsStructure creates a Windows SEC_CHANNEL_BINDINGS structure.
// This is the format that Windows SSPI expects for channel binding tokens.
// https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-sec_channel_bindings
func createChannelBindingsStructure(applicationData []byte) []byte {
	const headerSize = 32 // 8 DWORDs * 4 bytes each
	appDataLen := uint32(len(applicationData))
	appDataOffset := uint32(headerSize)

	buf := make([]byte, headerSize+len(applicationData))

	// All initiator and acceptor fields are 0 for TLS channel binding.
	binary.LittleEndian.PutUint32(buf[24:], appDataLen)    // cbApplicationDataLength
	binary.LittleEndian.PutUint32(buf[28:], appDataOffset) // dwApplicationDataOffset

	copy(buf[headerSize:], applicationData)

	return buf
}

// calculateCertificateHash implements RFC 5929 certificate hash calculation.
// https://www.rfc-editor.org/rfc/rfc5929.html#section-4.1
func calculateCertificateHash(cert *x509.Certificate) []byte {
	var hashFunc crypto.Hash

	switch cert.SignatureAlgorithm {
	case x509.SHA256WithRSA,
		x509.SHA256WithRSAPSS,
		x509.ECDSAWithSHA256,
		x509.DSAWithSHA256:

		hashFunc = crypto.SHA256
	case x509.SHA384WithRSA,
		x509.SHA384WithRSAPSS,
		x509.ECDSAWithSHA384:

		hashFunc = crypto.SHA384
	case x509.SHA512WithRSA,
		x509.SHA512WithRSAPSS,
		x509.ECDSAWithSHA512:

		hashFunc = crypto.SHA512
	case x509.MD5WithRSA,
		x509.SHA1WithRSA,
		x509.ECDSAWithSHA1,
		x509.DSAWithSHA1:

		hashFunc = crypto.SHA256
	default:
		return nil
	}

	hasher := hashFunc.New()

	// Important to hash cert in DER format.
	hasher.Write(cert.Raw)
	return hasher.Sum(nil)
}
