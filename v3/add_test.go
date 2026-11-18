package ldap

import (
	"fmt"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
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

func TestConn_AddWithResult(t *testing.T) {
	l, err := getTestConnection(true)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	dn := "cn=new_user_with_result,ou=people,dc=example,dc=com"
	// Delete the entry if it already exists from previous test runs
	_ = l.Del(NewDelRequest(dn, nil))

	t.Run("create entry", func(t *testing.T) {
		result, err := l.AddWithResult(&AddRequest{
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
		if assert.NotNil(t, result) {
			assert.Empty(t, result.Referral)
		}
	})
	t.Run("create entry with no attributes", func(t *testing.T) {
		_, err := l.AddWithResult(&AddRequest{
			DN:         dn,
			Attributes: nil,
		})
		assert.Error(t, err)
		assert.Truef(t, IsErrorWithCode(err, LDAPResultProtocolError), "Expected LDAPResultProtocolError, got %v", err)
	})
	t.Run("empty AddRequest", func(t *testing.T) {
		_, err := l.AddWithResult(&AddRequest{})
		assert.Error(t, err)
	})
	t.Run("nil AddRequest", func(t *testing.T) {
		_, err := l.AddWithResult(nil)
		assert.Error(t, err)
	})
}

// runAddWithResult drives AddWithResult against a packetTranslatorConn,
// replying to the request with the packet built by respFn (which receives the
// request message id). It returns the AddWithResult result.
func runAddWithResult(t *testing.T, respFn func(msgID int64) *ber.Packet) (*AddResult, error) {
	t.Helper()

	ptc := newPacketTranslatorConn()
	conn := NewConn(ptc, false)
	conn.Start()
	defer func() { _ = conn.Close() }()

	type result struct {
		res *AddResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		req := NewAddRequest("cn=test,dc=example,dc=com", nil)
		req.Attribute("objectClass", []string{"top", "person"})
		res, err := conn.AddWithResult(req)
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
		t.Fatal("timed out waiting for AddWithResult")
		return nil, nil
	}
}

// A reply that is not an AddResponse, or that has no protocolOp at all, says
// nothing about the outcome of the add, so AddWithResult must return an error
// instead of a result.
func TestAddWithResult_MalformedOrUnexpectedResponse(t *testing.T) {
	tests := []struct {
		name string
		resp func(msgID int64) *ber.Packet
	}{
		{
			name: "missing protocolOp",
			resp: func(msgID int64) *ber.Packet {
				env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
				env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
				return env
			},
		},
		{
			name: "ExtendedResponse protocolError",
			resp: func(msgID int64) *ber.Packet {
				return newDecodeEnvelope(msgID, newResultProtocolOp(ApplicationExtendedResponse, int64(LDAPResultProtocolError)))
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := runAddWithResult(t, tc.resp)

			assert.Error(t, err)
			assert.Nil(t, res)
		})
	}
}

// An AddResponse is decoded into a result: success yields the response
// controls and a non-success result code is returned as an LDAP error.
func TestAddWithResult_AddResponse(t *testing.T) {
	res, err := runAddWithResult(t, func(msgID int64) *ber.Packet {
		env := newDecodeEnvelope(msgID, newResultProtocolOp(ApplicationAddResponse, int64(LDAPResultSuccess)))
		env.AppendChild(encodeControls([]Control{NewControlString("1.2.3.4", false, "value")}))
		return env
	})
	assert.NoError(t, err)
	if assert.NotNil(t, res) && assert.Len(t, res.Controls, 1) {
		assert.Equal(t, "1.2.3.4", res.Controls[0].GetControlType())
	}

	res, err = runAddWithResult(t, func(msgID int64) *ber.Packet {
		return newDecodeEnvelope(msgID, newResultProtocolOp(ApplicationAddResponse, int64(LDAPResultEntryAlreadyExists)))
	})
	assert.True(t, IsErrorWithCode(err, LDAPResultEntryAlreadyExists))
	assert.NotNil(t, res)
}
