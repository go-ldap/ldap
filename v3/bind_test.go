package ldap

import (
	"testing"
	"time"

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
	resp, err := computeResponse(params, "ldap/host", `a"b\c`, "secret")
	assert.NoError(t, err)
	assert.Contains(t, resp, `username="a\"b\\c"`)
}

func TestComputeResponseQuotesServerRealm(t *testing.T) {
	// realm and nonce come from the server challenge and are echoed back
	// inside quoted strings, so they need the same escaping.
	params := map[string]string{"realm": `r"x`, "nonce": "abc"}
	resp, err := computeResponse(params, "ldap/host", "user", "secret")
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

// TestSASLBindTokenExchangeShortInProgress feeds a saslBindInProgress response
// that omits the optional serverSaslCreds, so the protocolOp carries only the
// three LDAPResult components. The length guard before reading the creds child
// must reject it instead of indexing past the slice.
func TestSASLBindTokenExchangeShortInProgress(t *testing.T) {
	ptc := newPacketTranslatorConn()
	defer func() { _ = ptc.Close() }()

	conn := NewConn(ptc, false)
	conn.Start()
	defer func() { _ = conn.Close() }()

	type result struct {
		err       error
		panicked  bool
		panicData interface{}
	}
	resCh := make(chan result, 1)
	go func() {
		var res result
		defer func() {
			if r := recover(); r != nil {
				res.panicked = true
				res.panicData = r
			}
			resCh <- res
		}()
		_, res.err = conn.saslBindTokenExchange(nil, []byte("client-token"))
	}()

	req, err := ptc.ReceiveRequest()
	if err != nil {
		t.Fatalf("receive request: %v", err)
	}
	msgID := req.Children[0].Value.(int64)

	resp := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
	bindResp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Bind Response")
	bindResp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 14, "resultCode"))
	bindResp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	bindResp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	resp.AppendChild(bindResp)

	if err := ptc.SendResponse(resp); err != nil {
		t.Fatalf("send response: %v", err)
	}

	select {
	case res := <-resCh:
		if res.panicked {
			t.Fatalf("saslBindTokenExchange panicked on short response: %v", res.panicData)
		}
		if res.err == nil {
			t.Fatal("expected an error for a saslBindInProgress response without serverSaslCreds")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("saslBindTokenExchange did not return")
	}
}
