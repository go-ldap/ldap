//go:build windows
// +build windows

package gssapi

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/kerberos"
)

// SSPIClient implements ldap.GSSAPIClient interface.
// Depends on secur32.dll.
type SSPIClient struct {
	creds *sspi.Credentials
	ctx   *kerberos.ClientContext
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
	sspiFlags := uint32(sspi.ISC_REQ_INTEGRITY | sspi.ISC_REQ_CONFIDENTIALITY | sspi.ISC_REQ_MUTUAL_AUTH)

	switch token {
	case nil:
		ctx, completed, output, err := kerberos.NewClientContextWithFlags(c.creds, target, sspiFlags)
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
