package ldap

import (
	"context"
	"errors"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// mustNotPanic runs f and fails the test if it panics.
func mustNotPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("%s panicked: %v", name, r)
		}
	}()
	f()
}

func newDecodeEnvelope(msgID int64, op *ber.Packet) *ber.Packet {
	env := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	env.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
	env.AppendChild(op)
	return env
}

func newResultProtocolOp(tag int, resultCode int64, extra ...*ber.Packet) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(tag), nil, "result")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, resultCode, "resultCode"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "errorMessage"))
	for _, e := range extra {
		op.AppendChild(e)
	}
	return op
}

// runSearchResponse drives conn.Search against a packetTranslatorConn and
// answers with the single packet built by respFn.
func runSearchResponse(t *testing.T, respFn func(msgID int64) *ber.Packet) (*SearchResult, error) {
	t.Helper()

	ptc := newPacketTranslatorConn()
	conn := NewConn(ptc, false)
	conn.Start()
	defer func() { _ = conn.Close() }()

	type result struct {
		res *SearchResult
		err error
	}
	done := make(chan result, 1)
	go func() {
		res, err := conn.Search(NewSearchRequest("dc=example,dc=com", ScopeWholeSubtree, DerefAlways, 0, 0, false, "(objectClass=*)", nil, nil))
		done <- result{res, err}
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
		t.Fatal("timed out waiting for Search")
		return nil, nil
	}
}

// TestSearchMalformedEntryResponses feeds structurally invalid search
// responses; Search must return an error rather than panicking.
func TestSearchMalformedEntryResponses(t *testing.T) {
	tests := []struct {
		name string
		op   func() *ber.Packet
	}{
		{
			name: "entry with no children",
			op: func() *ber.Packet {
				return ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "Search Result Entry")
			},
		},
		{
			name: "entry with constructed object name",
			op: func() *ber.Packet {
				op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "Search Result Entry")
				// A constructed-form OCTET STRING decodes with a nil Value, so the
				// object name cannot be read as a string.
				dn := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagOctetString, nil, "Object Name")
				dn.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn=x", "content"))
				op.AppendChild(dn)
				op.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes"))
				return op
			},
		},
		{
			name: "entry with dn but no attributes element",
			op: func() *ber.Packet {
				op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "Search Result Entry")
				op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn=x", "Object Name"))
				return op
			},
		},
		{
			name: "referral with no children",
			op: func() *ber.Packet {
				return ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultReference, nil, "Search Result Reference")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op := tt.op()
			var res *SearchResult
			var err error
			mustNotPanic(t, tt.name, func() {
				res, err = runSearchResponse(t, func(msgID int64) *ber.Packet {
					return newDecodeEnvelope(msgID, op)
				})
			})
			_ = res
			if err == nil {
				t.Fatal("expected an error for malformed search response, got nil")
			}
		})
	}
}

// TestSearchAsyncMalformedEntryResponse verifies the streaming decoder path
// (response.go) surfaces a malformed entry as an error instead of panicking.
func TestSearchAsyncMalformedEntryResponse(t *testing.T) {
	ptc := newPacketTranslatorConn()
	conn := NewConn(ptc, false)
	conn.Start()
	defer func() { _ = conn.Close() }()

	go func() {
		req, err := ptc.ReceiveRequest()
		if err != nil {
			return
		}
		msgID := req.Children[0].Value.(int64)
		entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "Search Result Entry")
		_ = ptc.SendResponse(newDecodeEnvelope(msgID, entry))
	}()

	r := conn.SearchAsync(context.Background(), NewSearchRequest("dc=example,dc=com", ScopeWholeSubtree, DerefAlways, 0, 0, false, "(objectClass=*)", nil, nil), 1)
	mustNotPanic(t, "SearchAsync malformed entry", func() {
		for r.Next() {
		}
	})
	if r.Err() == nil {
		t.Fatal("expected an error from malformed SearchAsync entry, got nil")
	}
}

// TestSaslBindTokenExchangeShortReferral reproduces the off-by-one that read
// Children[3] after only checking for three children. A Bind Response with
// exactly three children must not panic.
func TestSaslBindTokenExchangeShortReferral(t *testing.T) {
	ptc := newPacketTranslatorConn()
	conn := NewConn(ptc, false)
	conn.Debug = true
	conn.Start()
	defer func() { _ = conn.Close() }()

	done := make(chan error, 1)
	go func() {
		_, err := conn.saslBindTokenExchange(nil, []byte("token"))
		done <- err
	}()

	req, err := ptc.ReceiveRequest()
	if err != nil {
		t.Fatalf("receive request: %s", err)
	}
	msgID := req.Children[0].Value.(int64)

	// Only three children: resultCode (14 = sasl bind in progress) plus the
	// mandatory matchedDN and diagnosticMessage. The optional referral is absent.
	bindResp := newResultProtocolOp(ApplicationBindResponse, 14)

	mustNotPanic(t, "saslBindTokenExchange short referral", func() {
		if err := ptc.SendResponse(newDecodeEnvelope(msgID, bindResp)); err != nil {
			t.Errorf("send response: %s", err)
		}
		select {
		case err := <-done:
			if err == nil {
				t.Error("expected error for non-success bind response, got nil")
			}
		case <-time.After(3 * time.Second):
			t.Error("timed out waiting for saslBindTokenExchange")
		}
	})
}

// TestDecodeControlMissingValueNoPanic covers value-requiring controls that
// previously dereferenced a nil control value.
func TestDecodeControlMissingValueNoPanic(t *testing.T) {
	controlTypes := []string{
		ControlTypeDirSync,
		ControlTypeSyncState,
		ControlTypeSyncDone,
		ControlTypeSyncInfo,
		ControlTypeServerSideSorting,
		ControlTypeBeheraPasswordPolicy,
	}
	for _, ct := range controlTypes {
		t.Run(ct, func(t *testing.T) {
			p := newTestEnvelope(newTestString(ct)) // type only, no criticality/value
			var err error
			mustNotPanic(t, ct, func() {
				_, err = DecodeControl(p)
			})
			if err == nil {
				t.Fatalf("expected error for %s without a value, got nil", ct)
			}
		})
	}
}

// TestDecodeControlStructuralIdentification verifies that the second control
// element is identified by its ASN.1 tag, not by the Go type of its Value.
func TestDecodeControlStructuralIdentification(t *testing.T) {
	t.Run("octet string with unexpected go type is a value", func(t *testing.T) {
		control := newTestEnvelope(newTestString("1.2.3.4.5"))

		// An OCTET STRING whose Value is not a Go string must still be
		// classified as the control value by its tag, not as criticality.
		weird := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value")
		weird.Value = int64(42)
		weird.Data.WriteString("raw-value")
		control.Children = append(control.Children, weird)

		c, err := DecodeControl(control)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cs, ok := c.(*ControlString)
		if !ok {
			t.Fatalf("expected *ControlString, got %T", c)
		}
		if cs.Criticality {
			t.Error("OCTET STRING must not be treated as criticality")
		}
		if cs.ControlValue != "raw-value" {
			t.Errorf("ControlValue = %q, want %q", cs.ControlValue, "raw-value")
		}
	})

	t.Run("boolean tag is criticality", func(t *testing.T) {
		control := newTestEnvelope(newTestString("1.2.3.4.5"), newTestBool(true))
		c, err := DecodeControl(control)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		cs, ok := c.(*ControlString)
		if !ok {
			t.Fatalf("expected *ControlString, got %T", c)
		}
		if !cs.Criticality {
			t.Error("BOOLEAN child must be treated as criticality")
		}
	})
}

func TestNewResponseControlDirSyncMalformed(t *testing.T) {
	tests := []struct {
		name  string
		value *ber.Packet
	}{
		{name: "nil value", value: nil},
		{name: "no children", value: ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value")},
		{name: "wrong flag type", value: func() *ber.Packet {
			v := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value")
			seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "DirSync")
			seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "not-int", "Flags"))
			seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 5, "MaxAttrCount"))
			seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Cookie"))
			v.AppendChild(seq)
			return v
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			mustNotPanic(t, tt.name, func() {
				_, err = NewResponseControlDirSync(tt.value)
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestNewControlSyncStateMalformed(t *testing.T) {
	tests := []struct {
		name string
		pkt  *ber.Packet
	}{
		{name: "nil", pkt: nil},
		{name: "one child", pkt: newTestEnvelope(newTestInt(0))},
		{name: "wrong state type", pkt: newTestEnvelope(newTestString("not-int"), newTestString("uuid"))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			mustNotPanic(t, tt.name, func() {
				_, err = NewControlSyncState(tt.pkt)
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestNewControlServerSideSortingMalformed(t *testing.T) {
	tests := []struct {
		name  string
		value *ber.Packet
	}{
		{name: "nil", value: nil},
		{name: "no data buffer", value: &ber.Packet{Identifier: ber.Identifier{ClassType: ber.ClassUniversal, TagType: ber.TypePrimitive, Tag: ber.TagOctetString}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			mustNotPanic(t, tt.name, func() {
				_, err = NewControlServerSideSorting(tt.value)
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestGetLDAPErrorMalformed(t *testing.T) {
	nilChild := newTestEnvelope(newTestInt(1))
	nilChild.Children = append(nilChild.Children, nil)

	shortResponse := newDecodeEnvelope(1, newResultProtocolOp(ApplicationModifyResponse, 0))
	shortResponse.Children[1].Children = shortResponse.Children[1].Children[:2]

	badResultCodeType := newDecodeEnvelope(1, newResultProtocolOp(ApplicationModifyResponse, 0))
	badResultCodeType.Children[1].Children[0].Value = "not-int"

	nilResultCode := newDecodeEnvelope(1, newResultProtocolOp(ApplicationModifyResponse, 0))
	nilResultCode.Children[1].Children[0].Value = nil

	nilMatchedDN := newDecodeEnvelope(1, newResultProtocolOp(ApplicationModifyResponse, 1))
	nilMatchedDN.Children[1].Children[1].Value = nil

	tests := []struct {
		name   string
		packet *ber.Packet
	}{
		{name: "nil packet", packet: nil},
		{name: "empty packet", packet: newTestEnvelope()},
		{name: "nil protocol op", packet: nilChild},
		{name: "short response", packet: shortResponse},
		{name: "result code wrong type", packet: badResultCodeType},
		{name: "nil result code", packet: nilResultCode},
		{name: "nil matchedDN", packet: nilMatchedDN},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			mustNotPanic(t, tt.name, func() {
				err = GetLDAPError(tt.packet)
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestUnpackAttributesBoundsMalformed(t *testing.T) {
	validAttr := func() *ber.Packet {
		attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
		attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn", "type"))
		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "value", "value"))
		attr.AppendChild(vals)
		return attr
	}

	nilAttribute := []*ber.Packet{nil}

	missingVals := validAttr()
	missingVals.Children = missingVals.Children[:1]

	nameWrongType := validAttr()
	nameWrongType.Children[0].Value = int64(1)

	valueWrongType := validAttr()
	valueWrongType.Children[1].Children[0].Value = int64(1)

	nilValue := validAttr()
	nilValue.Children[1].Children = append(nilValue.Children[1].Children, nil)

	tests := []struct {
		name     string
		children []*ber.Packet
	}{
		{name: "nil attribute", children: nilAttribute},
		{name: "missing vals", children: []*ber.Packet{missingVals}},
		{name: "name wrong type", children: []*ber.Packet{nameWrongType}},
		{name: "value wrong type", children: []*ber.Packet{valueWrongType}},
		{name: "nil value", children: []*ber.Packet{nilValue}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			mustNotPanic(t, tt.name, func() {
				_, err = unpackAttributes(tt.children)
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, ErrMalformedPacket) {
				t.Fatalf("expected ErrMalformedPacket, got %v", err)
			}
		})
	}
}

func TestAddLDAPDescriptionsMalformed(t *testing.T) {
	entryNoChildren := newDecodeEnvelope(1, ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "Search Result Entry"))

	tests := []struct {
		name   string
		packet *ber.Packet
	}{
		{name: "one child", packet: newTestEnvelope(newTestInt(1))},
		{name: "search result entry with no children", packet: entryNoChildren},
		{name: "search result entry with one child", packet: func() *ber.Packet {
			op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "Search Result Entry")
			op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn=x", "Object Name"))
			return newDecodeEnvelope(1, op)
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			mustNotPanic(t, tt.name, func() {
				err = addLDAPDescriptions(tt.packet)
			})
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestPacketHelpersDoNotPanicOnNil(t *testing.T) {
	// A sanity sweep: the helpers never panic and always report a
	// malformed-packet error for nil input.
	calls := []struct {
		name string
		f    func() error
	}{
		{"packetChild", func() error { _, err := packetChild(nil, 0); return err }},
		{"packetChildIfPresent", func() error { _, _, err := packetChildIfPresent(nil, 0); return err }},
		{"packetChildCount", func() error { _, err := packetChildCount(nil, 1, 1, "x"); return err }},
		{"packetString", func() error { _, err := packetString(nil); return err }},
		{"packetInt64", func() error { _, err := packetInt64(nil); return err }},
		{"packetBool", func() error { _, err := packetBool(nil); return err }},
		{"packetData", func() error { _, err := packetData(nil); return err }},
	}
	for _, c := range calls {
		t.Run(c.name, func(t *testing.T) {
			var err error
			mustNotPanic(t, c.name, func() { err = c.f() })
			if !errors.Is(err, ErrMalformedPacket) {
				t.Fatalf("expected ErrMalformedPacket, got %v", err)
			}
		})
	}
}
