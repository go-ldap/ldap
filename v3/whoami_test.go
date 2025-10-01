package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConn_WhoAmI(t *testing.T) {
	l, err := getTestConnection(false)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	t.Run("unauthenticated", func(t *testing.T) {
		result, err := l.WhoAmI(nil)
		assert.NoError(t, err)
		assert.Equal(t, "", result.AuthzID)
	})
	t.Run("authenticated", func(t *testing.T) {
		assert.NoError(t, l.Bind("cn=admin,"+baseDN, "admin123"))
		result, err := l.WhoAmI(nil)
		assert.NoError(t, err)
		assert.Equal(t, "dn:cn=admin,"+baseDN, result.AuthzID)
	})
}
