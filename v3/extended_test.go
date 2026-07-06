package ldap

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
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

// TestExtendedResponseNameOmitted feeds a successful ExtendedResponse that
// carries a responseValue but no responseName. The resultCode is a universal
// ENUMERATED whose tag number matches responseName [10]; decoding must not
// report the result code as the name.
func TestExtendedResponseNameOmitted(t *testing.T) {
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
		extResp.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.TagEmbeddedPDV, "payload", "responseValue"))
		resp.AppendChild(extResp)
		_ = ptc.SendResponse(resp)
	}()

	result, err := conn.Extended(NewExtendedRequest("1.2.3.4", nil))
	assert.NoError(t, err)
	assert.Equal(t, "", result.Name)
	assert.NotNil(t, result.Value)
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
