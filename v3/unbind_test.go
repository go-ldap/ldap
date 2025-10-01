package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConn_Unbind(t *testing.T) {
	t.Run("unbind", func(t *testing.T) {
		l, err := getTestConnection(false)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()

		assert.NoError(t, l.Unbind())
	})
	// We should not be able to reuse the connection after unbinding.
	t.Run("reuse connection", func(t *testing.T) {
		l, err := getTestConnection(false)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()

		assert.NoError(t, l.Unbind())

		err = l.Unbind()
		assert.True(t, IsErrorWithCode(err, ErrorNetwork), "Expected ErrorNetwork, got %v", err)
	})
}
