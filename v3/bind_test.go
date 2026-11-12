package ldap

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/stretchr/testify/assert"
)

func TestConn_Bind(t *testing.T) {
	l, err := getTestConnection(false)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	tests := []struct {
		name      string
		dn        string
		password  string
		wantError bool
		errorCode uint16
	}{
		{
			name:      "invalid credentials",
			dn:        "cn=admin," + baseDN,
			password:  "AAAAAAAAAA",
			wantError: true,
			errorCode: LDAPResultInvalidCredentials,
		},
		{
			name:      "no credentials",
			dn:        "",
			password:  "",
			wantError: true,
			errorCode: ErrorEmptyPassword,
		},
		{
			name:      "valid credentials",
			dn:        "cn=admin," + baseDN,
			password:  "admin123",
			wantError: false,
			errorCode: LDAPResultSuccess,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := l.Bind(tt.dn, tt.password)
			if tt.wantError {
				assert.Error(t, err)
				assert.Truef(t, IsErrorWithCode(err, tt.errorCode), "Expected error code %v, got %d", tt.errorCode, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestComputeResponseQuotesSpecialChars(t *testing.T) {
	// A username carrying a double quote or backslash must be emitted as a
	// properly escaped DIGEST-MD5 quoted string, otherwise it breaks out of
	// the username directive and injects further directives into the response.
	params := map[string]string{"realm": "example.com", "nonce": "abc"}
	resp, _, err := computeResponse(params, "ldap/host", `a"b\c`, "secret")
	assert.NoError(t, err)
	assert.Contains(t, resp, `username="a\"b\\c"`)
}

func TestComputeResponseQuotesServerRealm(t *testing.T) {
	// realm and nonce come from the server challenge and are echoed back
	// inside quoted strings, so they need the same escaping.
	params := map[string]string{"realm": `r"x`, "nonce": "abc"}
	resp, _, err := computeResponse(params, "ldap/host", "user", "secret")
	assert.NoError(t, err)
	assert.Contains(t, resp, `realm="r\"x"`)
}

func TestParseParamsUnescapesQuotedPair(t *testing.T) {
	// The DIGEST-MD5 challenge is sent by the server as comma-separated
	// directives whose values are quoted strings. Per RFC 2831 section 7.1 a
	// literal double quote or backslash inside such a value is sent as a
	// quoted-pair (\" or \\), so the parser has to unescape it. Without that
	// the value is truncated at the escaped quote and the bind fails.
	params, err := parseParams(`realm="a\"b",nonce="c\\d"`)
	assert.NoError(t, err)
	assert.Equal(t, `a"b`, params["realm"])
	assert.Equal(t, `c\d`, params["nonce"])
}

func TestParseParamsLinearWhitespace(t *testing.T) {
	// The DIGEST-MD5 challenge is an RFC 2068 #rule (RFC 2831 section 2.1.1),
	// so a conforming server may put optional linear whitespace around the
	// comma directive separators. Every directive after the first must still be
	// keyed by its name; otherwise the leading space makes realm/nonce lookups
	// in computeResponse return empty and the bind digest is computed over the
	// wrong parameters.
	params, err := parseParams(`realm="example.com", nonce="abc123" , qop=auth`)
	assert.NoError(t, err)
	assert.Equal(t, "example.com", params["realm"])
	assert.Equal(t, "abc123", params["nonce"])
	assert.Equal(t, "auth", params["qop"])

	// Whitespace inside a quoted value is still significant and must be kept.
	params, err = parseParams(`realm="a b", nonce="c d"`)
	assert.NoError(t, err)
	assert.Equal(t, "a b", params["realm"])
	assert.Equal(t, "c d", params["nonce"])
}

func TestComputeRspauthRFC2831Example(t *testing.T) {
	// Worked example from RFC 2831 section 4: user "chris", password
	// "secret", with the server's final message carrying
	// rspauth=ea40f60335c427b5527b84dbabcdfffd.
	x := "chris:elwood.innosoft.com:secret"
	a1 := bytes.NewBuffer(md5Hash([]byte(x)))
	a1.WriteString(":OA6MG9tEQGm2hh:OA6MHXh6VqTrRk")
	ha1 := hex.EncodeToString(md5Hash(a1.Bytes()))

	rspauth := computeRspauth(ha1, "OA6MG9tEQGm2hh", "OA6MHXh6VqTrRk", "imap/elwood.innosoft.com")
	assert.Equal(t, "ea40f60335c427b5527b84dbabcdfffd", rspauth)
}

// digestMD5Rspauth computes, from the digest-response directives a client
// sent and the shared password, the response-auth value a genuine server
// would return (RFC 2831 section 2.1.3).
func digestMD5Rspauth(creds map[string]string, password string) string {
	x := creds["username"] + ":" + creds["realm"] + ":" + password
	a1 := bytes.NewBuffer(md5Hash([]byte(x)))
	a1.WriteString(":" + creds["nonce"] + ":" + creds["cnonce"])
	ha1 := hex.EncodeToString(md5Hash(a1.Bytes()))
	return computeRspauth(ha1, creds["nonce"], creds["cnonce"], creds["digest-uri"])
}

// serveDigestMD5Bind scripts the server side of a DIGEST-MD5 bind on ptc: it
// answers the first bind request with a challenge and the digest-response
// with success, carrying the serverSaslCreds produced by rspauthFor (an empty
// string omits the field). Errors are not reported here: the exchange breaking
// off surfaces as a bind error on the client side under test.
func serveDigestMD5Bind(ptc *packetTranslatorConn, rspauthFor func(creds map[string]string) string) {
	bindResponse := func(msgID int64, code int64, saslCreds string) *ber.Packet {
		envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "")
		envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
		response := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "")
		response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, code, "Result Code"))
		response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
		response.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Diagnostic Message"))
		if saslCreds != "" {
			response.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.TagObjectDescriptor, saslCreds, "Server SASL Credentials"))
		}
		envelope.AppendChild(response)
		return envelope
	}

	go func() {
		req, err := ptc.ReceiveRequest()
		if err != nil {
			return
		}
		msgID, err := packetInt64At(req, 0)
		if err != nil {
			return
		}
		challenge := `realm="example.com",nonce="OA6MG9tEQGm2hh",qop="auth",charset=utf-8,algorithm=md5-sess`
		if err := ptc.SendResponse(bindResponse(msgID, LDAPResultSaslBindInProgress, challenge)); err != nil {
			return
		}

		req, err = ptc.ReceiveRequest()
		if err != nil {
			return
		}
		msgID, err = packetInt64At(req, 0)
		if err != nil {
			return
		}
		auth, err := packetChild(req.Children[1], 2)
		if err != nil {
			return
		}
		digestResponse, err := packetStringAt(auth, 1)
		if err != nil {
			return
		}
		creds, err := parseParams(digestResponse)
		if err != nil {
			return
		}
		_ = ptc.SendResponse(bindResponse(msgID, LDAPResultSuccess, rspauthFor(creds)))
	}()
}

func TestDigestMD5BindVerifiesRspauth(t *testing.T) {
	// The success bind response of a DIGEST-MD5 bind must carry the
	// response-auth value computed from the shared secret (RFC 2831 section
	// 2.1.3); verifying it is what authenticates the server. A server that
	// omits it or returns a wrong value never proved knowledge of the
	// password, so the bind has to fail instead of reporting success.
	tests := []struct {
		name       string
		rspauthFor func(creds map[string]string) string
		wantErr    string
	}{
		{
			name: "valid rspauth",
			rspauthFor: func(creds map[string]string) string {
				return "rspauth=" + digestMD5Rspauth(creds, "secret")
			},
		},
		{
			name:       "missing rspauth",
			rspauthFor: func(map[string]string) string { return "" },
			wantErr:    "server did not send rspauth",
		},
		{
			name: "mismatched rspauth",
			rspauthFor: func(map[string]string) string {
				return "rspauth=" + strings.Repeat("0", 32)
			},
			wantErr: "rspauth mismatch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ptc := newPacketTranslatorConn()
			defer ptc.Close()
			conn := NewConn(ptc, false)
			conn.Start()
			defer conn.Close()

			serveDigestMD5Bind(ptc, tt.rspauthFor)

			err := conn.MD5Bind("ldap.example.com", "user", "secret")
			if tt.wantErr == "" {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}

func TestConn_UnauthenticatedBind(t *testing.T) {
	l, err := getTestConnection(false)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	err = l.UnauthenticatedBind("cn=admin," + baseDN)
	assert.Error(t, err)
	assert.Truef(t, IsErrorWithCode(err, LDAPResultUnwillingToPerform), "Expected LDAPResultUnwillingToPerform, got %v", err)
}
