package ldap

import (
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/stretchr/testify/assert"
)

// runPasswordModify drives PasswordModify against a packetTranslatorConn,
// replying to the request with the ExtendedResponse built by respFn (which
// receives the request message id). It returns the PasswordModify result.
func runPasswordModify(t *testing.T, respFn func(msgID int64) *ber.Packet) (*PasswordModifyResult, error) {
	t.Helper()

	ptc := newPacketTranslatorConn()
	conn := NewConn(ptc, false)
	conn.Start()
	defer func() { _ = conn.Close() }()

	type result struct {
		res *PasswordModifyResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := conn.PasswordModify(NewPasswordModifyRequest("", "", ""))
		done <- result{res: res, err: err}
	}()

	req, err := ptc.ReceiveRequest()
	if err != nil {
		t.Fatalf("receive request: %s", err)
	}
	msgID := req.Children[0].Value.(int64)

	if err := ptc.SendResponse(respFn(msgID)); err != nil {
		t.Fatalf("send response: %s", err)
	}

	select {
	case r := <-done:
		return r.res, r.err
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for PasswordModify")
		return nil, nil
	}
}

func passwordModifyEnvelope(msgID int64, responseValue *ber.Packet) *ber.Packet {
	extResp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedResponse, nil, "Extended Response")
	extResp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "resultCode"))
	extResp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	extResp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "errorMessage"))
	if responseValue != nil {
		extResp.AppendChild(responseValue)
	}

	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
	env.AppendChild(extResp)
	return env
}

// A server response whose responseValue field does not hold a valid BER
// element must surface an error rather than crashing the caller goroutine.
func TestPasswordModify_MalformedResponseValue(t *testing.T) {
	res, err := runPasswordModify(t, func(msgID int64) *ber.Packet {
		// 0x30 is the start of a SEQUENCE but the element is truncated, so
		// decoding the responseValue fails.
		responseValue := ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.TagEmbeddedPDV, string([]byte{0x30}), "responseValue")
		return passwordModifyEnvelope(msgID, responseValue)
	})

	assert.Error(t, err)
	assert.Nil(t, res)
}

// A well-formed responseValue still yields the generated password.
func TestPasswordModify_GeneratedPassword(t *testing.T) {
	res, err := runPasswordModify(t, func(msgID int64) *ber.Packet {
		seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PasswordModifyResponseValue")
		seq.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.TagEOC, "s3cr3t", "genPasswd"))
		responseValue := ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.TagEmbeddedPDV, string(seq.Bytes()), "responseValue")
		return passwordModifyEnvelope(msgID, responseValue)
	})

	assert.NoError(t, err)
	if assert.NotNil(t, res) {
		assert.Equal(t, "s3cr3t", res.GeneratedPassword)
	}
}
