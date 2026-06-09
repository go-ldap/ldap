package ldap

import (
	"testing"

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
