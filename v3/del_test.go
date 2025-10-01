package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConn_Del(t *testing.T) {
	l, err := getTestConnection(true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	dn := "cn=testuser,ou=people,dc=example,dc=com"

	// Remove the entry if it exists from previous test runs
	_ = l.Del(NewDelRequest(dn, nil))

	assert.NoError(t, l.Add(&AddRequest{
		DN: dn,
		Attributes: []Attribute{
			{
				Type: "objectClass",
				Vals: []string{"top", "person", "organizationalPerson", "inetOrgPerson"},
			},
			{
				Type: "cn",
				Vals: []string{"testuser"},
			},
			{
				Type: "givenName",
				Vals: []string{"Test User"},
			},
			{
				Type: "sn",
				Vals: []string{"Dummy"},
			},
		},
	}))
	t.Logf("Added user")

	tests := []struct {
		name      string
		dn        string
		wantErr   bool
		errorCode uint16
	}{
		{
			name:      "empty DN",
			dn:        "",
			wantErr:   true,
			errorCode: LDAPResultUnwillingToPerform,
		},
		{
			name:      "invalid DN",
			dn:        "AAAAAAAAAAAAAAAAAA",
			wantErr:   true,
			errorCode: LDAPResultInvalidDNSyntax,
		},
		{
			name:    "delete user",
			dn:      dn,
			wantErr: false,
		},
		{
			name:      "delete entry with children",
			dn:        "ou=people," + baseDN,
			wantErr:   true,
			errorCode: LDAPResultNotAllowedOnNonLeaf,
		},
		{
			name:      "delete non existing entry",
			dn:        "ou=nonexisting," + baseDN,
			wantErr:   true,
			errorCode: LDAPResultNoSuchObject,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delRequest := NewDelRequest(tt.dn, nil)
			err := l.Del(delRequest)
			if tt.wantErr && err != nil {
				assert.Error(t, err)
				assert.Truef(t, IsErrorWithCode(err, tt.errorCode), "Expected error with code %d, got %d", tt.errorCode, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	t.Run("nil DelRequest", func(t *testing.T) {
		err := l.Del(nil)
		assert.Error(t, err)
	})
}
