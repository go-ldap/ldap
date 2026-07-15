package ldap

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
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

// TestWhoAmIResponseValueOmitted feeds a successful WhoAmI ExtendedResponse that
// omits the optional responseValue [11]. A conformant server may leave it out;
// WhoAmI must not panic dereferencing a nil Value, and AuthzID is empty when the
// server sends no value.
func TestWhoAmIResponseValueOmitted(t *testing.T) {
	ptc := newPacketTranslatorConn()
	defer func() { _ = ptc.Close() }()

	conn := NewConn(ptc, false)
	conn.Start()
	defer func() { _ = conn.Close() }()

	go func() {
		req, err := ptc.ReceiveRequest()
		if err != nil {
			return
		}
		msgID := req.Children[0].Value.(int64)

		resp := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
		resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
		extResp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedResponse, nil, "Extended Response")
		extResp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "resultCode"))
		extResp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
		extResp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
		// responseValue [11] intentionally omitted.
		resp.AppendChild(extResp)
		_ = ptc.SendResponse(resp)
	}()

	result, err := conn.WhoAmI(nil)
	assert.NoError(t, err)
	assert.Equal(t, "", result.AuthzID)
}
