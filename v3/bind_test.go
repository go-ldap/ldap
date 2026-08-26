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
