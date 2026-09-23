package ldap

import (
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/stretchr/testify/assert"
)

const nmasUniversalPasswordOID = "2.16.840.1.113719.1.39.42.100.13"

func nmasRequestPayload(dn string) *ber.Packet {
	payload := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "NMAS payload")
	payload.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "version"))
	payload.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "dn"))
	return payload
}

func encodeExtendedRequest(t *testing.T, er *ExtendedRequest) *ber.Packet {
	t.Helper()
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, "MessageID"))
	if err := er.appendTo(env); err != nil {
		t.Fatal(err)
	}
	if len(env.Children) < 2 {
		t.Fatalf("expected message id and extended request, got %d children", len(env.Children))
	}
	return env.Children[1]
}

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

func TestExtendedRequest_appendToWrapsValueAsOctetString(t *testing.T) {
	payload := nmasRequestPayload("cn=user,o=org")
	ext := encodeExtendedRequest(t, NewExtendedRequest(nmasUniversalPasswordOID, payload))

	if ext.Tag != ApplicationExtendedRequest {
		t.Fatalf("extended request tag %d", ext.Tag)
	}
	if len(ext.Children) != 2 {
		t.Fatalf("expected requestName and requestValue, got %d children", len(ext.Children))
	}
	name := ext.Children[0]
	if name.ClassType != ber.ClassContext || name.Tag != 0 {
		t.Fatalf("requestName class=%d tag=%d", name.ClassType, name.Tag)
	}
	if name.Data.String() != nmasUniversalPasswordOID {
		t.Fatalf("requestName %q", name.Data.String())
	}
	val := ext.Children[1]
	if val.ClassType != ber.ClassContext || val.Tag != 1 {
		t.Fatalf("requestValue class=%d tag=%d, want context [1] OCTET STRING", val.ClassType, val.Tag)
	}
	if got, want := val.Data.Bytes(), payload.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("requestValue data\n got %x\nwant %x", got, want)
	}
}

func TestExtendedRequest_appendToLeavesPrewrappedValue(t *testing.T) {
	payload := nmasRequestPayload("cn=user,o=org")
	wrapped := ber.NewString(ber.ClassContext, ber.TypePrimitive, 1, string(payload.Bytes()), "prewrapped requestValue")
	ext := encodeExtendedRequest(t, NewExtendedRequest(nmasUniversalPasswordOID, wrapped))

	if len(ext.Children) != 2 {
		t.Fatalf("expected requestName and requestValue, got %d children", len(ext.Children))
	}
	val := ext.Children[1]
	if val.ClassType != ber.ClassContext || val.Tag != 1 {
		t.Fatalf("requestValue class=%d tag=%d", val.ClassType, val.Tag)
	}
	if got, want := val.Data.Bytes(), payload.Bytes(); !bytes.Equal(got, want) {
		t.Fatalf("prewrapped requestValue was re-encoded\n got %x\nwant %x", got, want)
	}
}

func TestExtendedRequest_appendToOmitsNilValue(t *testing.T) {
	ext := encodeExtendedRequest(t, NewExtendedRequest("1.3.6.1.4.1.4203.1.11.3", nil))
	if len(ext.Children) != 1 {
		t.Fatalf("expected only requestName, got %d children", len(ext.Children))
	}
	if ext.Children[0].ClassType != ber.ClassContext || ext.Children[0].Tag != 0 {
		t.Fatalf("requestName class=%d tag=%d", ext.Children[0].ClassType, ext.Children[0].Tag)
	}
}
