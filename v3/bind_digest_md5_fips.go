//go:build requirefips

package ldap

import (
	"errors"

	ber "github.com/go-asn1-ber/asn1-ber"
)

var errFIPSDigestMD5 = errors.New("ldap: DIGEST-MD5 is not available in FIPS mode; use GSSAPIBind (Kerberos) or SimpleBind over TLS")

// DigestMD5BindRequest represents a digest-md5 bind operation
type DigestMD5BindRequest struct {
	Host string
	// Username is the name of the Directory object that the client wishes to bind as
	Username string
	// Password is the credentials to bind with
	Password string
	// Controls are optional controls to send with the bind request
	Controls []Control
}

func (req *DigestMD5BindRequest) appendTo(_ *ber.Packet) error {
	return errFIPSDigestMD5
}

// DigestMD5BindResult contains the response from the server
type DigestMD5BindResult struct {
	Controls []Control
}

// MD5Bind is not available in FIPS mode. Use GSSAPIBind (Kerberos) or SimpleBind over TLS.
func (l *Conn) MD5Bind(host, username, password string) error {
	return errFIPSDigestMD5
}

// DigestMD5Bind is not available in FIPS mode. Use GSSAPIBind (Kerberos) or SimpleBind over TLS.
func (l *Conn) DigestMD5Bind(_ *DigestMD5BindRequest) (*DigestMD5BindResult, error) {
	return nil, errFIPSDigestMD5
}
