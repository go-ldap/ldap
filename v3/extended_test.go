package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConn_Extended(t *testing.T) {
	l, err := getTestConnection(true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	t.Run("nil ExtendedRequest", func(t *testing.T) {
		response, err := l.Extended(nil)
		assert.Nil(t, response)
		assert.Error(t, err)
	})
}

func TestExtendedRequest_WhoAmI(t *testing.T) {
	l, err := getTestConnection(true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	rfc4532req := NewExtendedRequest("1.3.6.1.4.1.4203.1.11.3", nil) // request value is <nil>

	var rfc4532resp *ExtendedResponse
	rfc4532resp, err = l.Extended(rfc4532req)
	assert.NoError(t, err)
	t.Logf("%#v\n", rfc4532resp)
}

func TestExtendedRequest_FastBind(t *testing.T) {
	conn, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	request := NewExtendedRequest("1.2.840.113556.1.4.1781", nil)
	_, err = conn.Extended(request)
	assert.Error(t, err)
}
