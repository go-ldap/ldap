package ldap

import (
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/stretchr/testify/assert"
)

// runModifyWithResult drives ModifyWithResult against a packetTranslatorConn,
// replying to the request with the packet built by respFn (which receives the
// request message id). It returns the ModifyWithResult result.
func runModifyWithResult(t *testing.T, respFn func(msgID int64) *ber.Packet) (*ModifyResult, error) {
	t.Helper()

	ptc := newPacketTranslatorConn()
	conn := NewConn(ptc, false)
	conn.Start()
	defer func() { _ = conn.Close() }()

	type result struct {
		res *ModifyResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		req := NewModifyRequest("cn=test,dc=example,dc=com", nil)
		req.Replace("description", []string{"updated"})
		res, err := conn.ModifyWithResult(req)
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
		t.Fatal("timed out waiting for ModifyWithResult")
		return nil, nil
	}
}

// A reply that is not a ModifyResponse says nothing about the outcome of the
// modification, so ModifyWithResult must report it like Modify does instead
// of returning a nil error.
func TestModifyWithResult_UnexpectedResponse(t *testing.T) {
	tests := []struct {
		name string
		op   func() *ber.Packet
	}{
		{
			// A bare LDAPResult SEQUENCE without the application tag, as sent
			// by servers that answer an unsupported operation generically.
			name: "untagged LDAPResult unwillingToPerform",
			op: func() *ber.Packet {
				op := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAPResult")
				op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(LDAPResultUnwillingToPerform), "resultCode"))
				op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
				op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "Operation not implemented by server", "errorMessage"))
				return op
			},
		},
		{
			name: "ExtendedResponse protocolError",
			op: func() *ber.Packet {
				return newResultProtocolOp(ApplicationExtendedResponse, int64(LDAPResultProtocolError))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := runModifyWithResult(t, func(msgID int64) *ber.Packet {
				return newDecodeEnvelope(msgID, tc.op())
			})

			assert.Error(t, err)
			assert.Nil(t, res)
		})
	}
}

// A ModifyResponse is still decoded as before: success yields a result and a
// non-success result code is returned as an LDAP error.
func TestModifyWithResult_ModifyResponse(t *testing.T) {
	res, err := runModifyWithResult(t, func(msgID int64) *ber.Packet {
		return newDecodeEnvelope(msgID, newResultProtocolOp(ApplicationModifyResponse, int64(LDAPResultSuccess)))
	})
	assert.NoError(t, err)
	assert.NotNil(t, res)

	res, err = runModifyWithResult(t, func(msgID int64) *ber.Packet {
		return newDecodeEnvelope(msgID, newResultProtocolOp(ApplicationModifyResponse, int64(LDAPResultInsufficientAccessRights)))
	})
	assert.True(t, IsErrorWithCode(err, LDAPResultInsufficientAccessRights))
	assert.NotNil(t, res)
}
