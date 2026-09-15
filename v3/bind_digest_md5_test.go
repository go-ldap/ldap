//go:build !requirefips

package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
