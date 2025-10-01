package ldap

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConn_Add(t *testing.T) {
	l, err := getTestConnection(true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	dn := "cn=new_user,ou=people,dc=example,dc=com"
	// Delete the entry if it already exists from previous test runs
	_ = l.Del(NewDelRequest(dn, nil))

	t.Run("create entry", func(t *testing.T) {
		err := l.Add(&AddRequest{
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
		})
		assert.NoError(t, err)
	})
	t.Run("create entry with no attributes", func(t *testing.T) {
		err := l.Add(&AddRequest{
			DN:         dn,
			Attributes: nil,
		})
		assert.Error(t, err)
		assert.Truef(t, IsErrorWithCode(err, LDAPResultProtocolError), "Expected LDAPResultProtocolError, got %v", err)
	})
	t.Run("empty AddRequest", func(t *testing.T) {
		err := l.Add(&AddRequest{})
		assert.Error(t, err)
	})
	t.Run("nil AddRequest", func(t *testing.T) {
		err := l.Add(nil)
		fmt.Println("expected AddRequest, got nil")
		assert.Error(t, err)
	})
}
