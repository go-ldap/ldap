//go:build requirefips

package ldap

import (
	"errors"

	ber "github.com/go-asn1-ber/asn1-ber"
)

var errFIPSNTLM = errors.New("ldap: NTLM bind is not available in FIPS mode; use GSSAPIBind (Kerberos)")

// NTLMBindRequest represents an NTLMSSP bind operation
type NTLMBindRequest struct {
	// Domain is the AD Domain to authenticate too. If not specified, it will be grabbed from the NTLMSSP Challenge
	Domain string
	// Username is the name of the Directory object that the client wishes to bind as
	Username string
	// Password is the credentials to bind with
	Password string
	// AllowEmptyPassword sets whether the client allows binding with an empty password
	// (normally used for unauthenticated bind).
	AllowEmptyPassword bool
	// Hash is the hex NTLM hash to bind with. Password or hash must be provided
	Hash string
	// Controls are optional controls to send with the bind request
	Controls []Control
	// Negotiator allows to specify a custom NTLM negotiator.
	Negotiator NTLMNegotiator
}

// NTLMNegotiator is an abstraction of an NTLM implementation that produces and
// processes NTLM binary tokens.
type NTLMNegotiator interface {
	Negotiate(domain string, workstation string) ([]byte, error)
	ChallengeResponse(challenge []byte, username string, hash string) ([]byte, error)
}

func (req *NTLMBindRequest) appendTo(_ *ber.Packet) error {
	return errFIPSNTLM
}

// NTLMBindResult contains the response from the server
type NTLMBindResult struct {
	Controls []Control
}

// NTLMBind is not available in FIPS mode. Use GSSAPIBind (Kerberos) instead.
func (l *Conn) NTLMBind(domain, username, password string) error {
	return errFIPSNTLM
}

// NTLMUnauthenticatedBind is not available in FIPS mode. Use GSSAPIBind (Kerberos) instead.
func (l *Conn) NTLMUnauthenticatedBind(domain, username string) error {
	return errFIPSNTLM
}

// NTLMBindWithHash is not available in FIPS mode. Use GSSAPIBind (Kerberos) instead.
func (l *Conn) NTLMBindWithHash(domain, username, hash string) error {
	return errFIPSNTLM
}

// NTLMChallengeBind is not available in FIPS mode. Use GSSAPIBind (Kerberos) instead.
func (l *Conn) NTLMChallengeBind(_ *NTLMBindRequest) (*NTLMBindResult, error) {
	return nil, errFIPSNTLM
}
