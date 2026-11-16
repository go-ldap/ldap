package ldap

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const testExtendedAsyncOID = "1.3.6.1.4.1.99999.1"

// newIntermediateResponsePacket builds an LDAPMessage carrying an
// IntermediateResponse. An empty name or a nil value omits the element.
func newIntermediateResponsePacket(msgID int64, name string, value []byte, controls ...Control) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationIntermediateResponse, nil, "Intermediate Response")
	if name != "" {
		op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, name, "responseName"))
	}
	if value != nil {
		op.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 1, string(value), "responseValue"))
	}
	env := newDecodeEnvelope(msgID, op)
	if len(controls) > 0 {
		env.AppendChild(encodeControls(controls))
	}
	return env
}

// startExtendedAsyncServer starts a Conn on a packetTranslatorConn. serve is
// run in a goroutine with the message ID of the first request received.
func startExtendedAsyncServer(t *testing.T, serve func(ptc *packetTranslatorConn, msgID int64)) (*Conn, *packetTranslatorConn) {
	t.Helper()
	ptc := newPacketTranslatorConn()
	conn := NewConn(ptc, false)
	conn.Start()
	t.Cleanup(func() {
		_ = ptc.Close()
		_ = conn.Close()
	})
	go func() {
		request, err := ptc.ReceiveRequest()
		if err != nil {
			return
		}
		msgID, err := packetInt64At(request, 0)
		if err != nil {
			t.Errorf("request without message ID: %v", err)
			return
		}
		op, err := packetChild(request, 1)
		if err != nil || op.Tag != ApplicationExtendedRequest {
			t.Errorf("expected an extended request, got %v (%v)", op, err)
			return
		}
		serve(ptc, msgID)
	}()
	return conn, ptc
}

// nextWithTimeout calls r.Next and fails the test if it blocks too long.
func nextWithTimeout(t *testing.T, r ExtendedAsyncResponse) bool {
	t.Helper()
	result := make(chan bool, 1)
	go func() { result <- r.Next() }()
	select {
	case ok := <-result:
		return ok
	case <-time.After(5 * time.Second):
		t.Fatal("ExtendedAsyncResponse.Next blocked")
		return false
	}
}

func TestExtendedAsync_IntermediateResponsesThenFinal(t *testing.T) {
	control := NewControlManageDsaIT(true)
	conn, _ := startExtendedAsyncServer(t, func(ptc *packetTranslatorConn, msgID int64) {
		_ = ptc.SendResponse(newIntermediateResponsePacket(msgID, "1.2.3.1", []byte{0x30, 0x03, 0x02, 0x01, 0x07}))
		_ = ptc.SendResponse(newIntermediateResponsePacket(msgID, "", []byte("no name")))
		_ = ptc.SendResponse(newIntermediateResponsePacket(msgID, "1.2.3.3", nil, control))
		_ = ptc.SendResponse(newExtendedResponsePacket(msgID, LDAPResultSuccess, "1.2.3.4", []byte("final")))
	})

	r := conn.ExtendedAsync(context.Background(), NewExtendedRequest(testExtendedAsyncOID, nil), 0)

	type want struct {
		name     string
		value    []byte
		controls int
	}
	for i, w := range []want{
		{"1.2.3.1", []byte{0x30, 0x03, 0x02, 0x01, 0x07}, 0},
		{"", []byte("no name"), 0},
		{"1.2.3.3", nil, 1},
	} {
		if !nextWithTimeout(t, r) {
			t.Fatalf("intermediate %d: Next returned false, err %v", i, r.Err())
		}
		got := r.Intermediate()
		if got.Name != w.name {
			t.Errorf("intermediate %d: name %q, want %q", i, got.Name, w.name)
		}
		switch {
		case w.value == nil && got.Value != nil:
			t.Errorf("intermediate %d: unexpected value %v", i, got.Value)
		case w.value != nil && (got.Value == nil || !bytes.Equal(got.Value.Data.Bytes(), w.value)):
			t.Errorf("intermediate %d: value %v, want %x", i, got.Value, w.value)
		}
		if len(got.Controls) != w.controls {
			t.Errorf("intermediate %d: %d controls, want %d", i, len(got.Controls), w.controls)
		}
	}
	if nextWithTimeout(t, r) {
		t.Fatal("Next must return false after the final response")
	}
	if r.Err() != nil {
		t.Fatalf("unexpected error: %v", r.Err())
	}
	if r.Intermediate() != nil {
		t.Error("Intermediate must be nil once Next returned false")
	}
	final := r.Response()
	if final == nil || final.Name != "1.2.3.4" || final.Value == nil || final.Value.Data.String() != "final" {
		t.Fatalf("final response: %+v", final)
	}
	if r.Next() {
		t.Fatal("Next must keep returning false")
	}
}

func TestExtendedAsync_FinalErrorKeepsResponse(t *testing.T) {
	conn, _ := startExtendedAsyncServer(t, func(ptc *packetTranslatorConn, msgID int64) {
		_ = ptc.SendResponse(newExtendedResponsePacket(msgID, LDAPResultProtocolError, "1.2.3.4", []byte("rejected items")))
	})
	r := conn.ExtendedAsync(context.Background(), NewExtendedRequest(testExtendedAsyncOID, nil), 1)
	if nextWithTimeout(t, r) {
		t.Fatal("no intermediate response expected")
	}
	if !IsErrorWithCode(r.Err(), LDAPResultProtocolError) {
		t.Fatalf("expected the protocolError result, got %v", r.Err())
	}
	if final := r.Response(); final == nil || final.Value == nil || final.Value.Data.String() != "rejected items" {
		t.Fatalf("the responseValue of a failed operation must be available, got %+v", final)
	}
}

func TestExtendedAsync_ContextCancelled(t *testing.T) {
	conn, _ := startExtendedAsyncServer(t, func(ptc *packetTranslatorConn, msgID int64) {
		_ = ptc.SendResponse(newIntermediateResponsePacket(msgID, "1.2.3.1", []byte("first")))
		// then the server keeps the operation open
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := conn.ExtendedAsync(ctx, NewExtendedRequest(testExtendedAsyncOID, nil), 4)
	if !nextWithTimeout(t, r) {
		t.Fatalf("first intermediate: %v", r.Err())
	}
	cancel()
	if nextWithTimeout(t, r) {
		t.Fatal("Next must return false once ctx is cancelled")
	}
	if !errors.Is(r.Err(), context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", r.Err())
	}
	if r.Response() != nil {
		t.Fatal("no final response was received")
	}
}

func TestExtendedAsync_ConnectionClosed(t *testing.T) {
	conn, _ := startExtendedAsyncServer(t, func(ptc *packetTranslatorConn, msgID int64) {
		_ = ptc.SendResponse(newIntermediateResponsePacket(msgID, "1.2.3.1", []byte("first")))
		time.Sleep(50 * time.Millisecond)
		_ = ptc.Close()
	})
	r := conn.ExtendedAsync(context.Background(), NewExtendedRequest(testExtendedAsyncOID, nil), 4)
	if !nextWithTimeout(t, r) {
		t.Fatalf("first intermediate: %v", r.Err())
	}
	if nextWithTimeout(t, r) {
		t.Fatal("Next must return false when the connection is closed")
	}
	if r.Err() == nil {
		t.Fatal("a closed connection must end the operation with an error")
	}
	if r.Response() != nil {
		t.Fatal("no final response was received")
	}
}

func TestExtendedAsync_ManyIntermediateResponsesInOrder(t *testing.T) {
	const count = 1000
	conn, _ := startExtendedAsyncServer(t, func(ptc *packetTranslatorConn, msgID int64) {
		for i := 0; i < count; i++ {
			_ = ptc.SendResponse(newIntermediateResponsePacket(msgID, "1.2.3.1", []byte{byte(i >> 8), byte(i)}))
		}
		_ = ptc.SendResponse(newExtendedResponsePacket(msgID, LDAPResultSuccess, "", nil))
	})
	r := conn.ExtendedAsync(context.Background(), NewExtendedRequest(testExtendedAsyncOID, nil), 0)
	for i := 0; i < count; i++ {
		if !nextWithTimeout(t, r) {
			t.Fatalf("intermediate %d: %v", i, r.Err())
		}
		if got := r.Intermediate().Value.Data.Bytes(); !bytes.Equal(got, []byte{byte(i >> 8), byte(i)}) {
			t.Fatalf("intermediate %d out of order: %x", i, got)
		}
	}
	if nextWithTimeout(t, r) || r.Err() != nil || r.Response() == nil {
		t.Fatalf("final response: %+v, err %v", r.Response(), r.Err())
	}
}

func TestExtendedAsync_UnexpectedResponse(t *testing.T) {
	conn, _ := startExtendedAsyncServer(t, func(ptc *packetTranslatorConn, msgID int64) {
		_ = ptc.SendResponse(newDecodeEnvelope(msgID, newResultProtocolOp(ApplicationSearchResultDone, 0)))
	})
	r := conn.ExtendedAsync(context.Background(), NewExtendedRequest(testExtendedAsyncOID, nil), 1)
	if nextWithTimeout(t, r) || r.Err() == nil {
		t.Fatalf("an unexpected response must end the operation with an error, got %v", r.Err())
	}
}

func TestExtendedAsync_NilRequest(t *testing.T) {
	conn, _ := startExtendedAsyncServer(t, func(*packetTranslatorConn, int64) {})
	r := conn.ExtendedAsync(context.Background(), nil, 0)
	if nextWithTimeout(t, r) || r.Err() == nil {
		t.Fatalf("a nil request must fail, got %v", r.Err())
	}
}

func TestDecodeIntermediateResponse(t *testing.T) {
	got, err := decodeIntermediateResponse(newIntermediateResponsePacket(1, "1.2.3", []byte("v"), NewControlManageDsaIT(false)))
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "1.2.3" || got.Value.Data.String() != "v" || len(got.Controls) != 1 {
		t.Fatalf("decoded %+v", got)
	}
	empty, err := decodeIntermediateResponse(newIntermediateResponsePacket(1, "", nil))
	if err != nil || empty.Name != "" || empty.Value != nil || len(empty.Controls) != 0 {
		t.Fatalf("empty intermediate response: %+v, %v", empty, err)
	}
	if _, err := decodeIntermediateResponse(newExtendedResponsePacket(1, 0, "", nil)); err == nil {
		t.Fatal("an extended response is not an intermediate response")
	}
}

// An ExtendedAsync whose messages are not read must not block the other
// requests of the connection, and its messages must not be lost.
func TestExtendedAsyncSlowConsumerDoesNotBlockConnection(t *testing.T) {
	conn, ptc := startDeliveryConn(t)
	const count = 10
	slowConsumerServer(ptc, count, func(msgID int64, i int) *ber.Packet {
		return newIntermediateResponsePacket(msgID, "1.2.3.1", []byte{byte(i)})
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := conn.ExtendedAsync(ctx, NewExtendedRequest(testExtendedAsyncOID, nil), 1)
	time.Sleep(200 * time.Millisecond) // let the messages arrive while nobody calls Next

	requireOtherRequestCompletes(t, conn)

	for i := 0; i < count; i++ {
		if !nextWithTimeout(t, r) {
			t.Fatalf("intermediate %d: %v", i, r.Err())
		}
		if got := r.Intermediate().Value.Data.Bytes(); len(got) != 1 || got[0] != byte(i) {
			t.Fatalf("intermediate %d: %x", i, got)
		}
	}
}

// Two ExtendedAsync on the same connection, with interleaved messages: each one
// receives its own messages, in order, while the other is not being read.
func TestInterleavedExtendedAsyncOnOneConnection(t *testing.T) {
	conn, ptc := startDeliveryConn(t)
	const count = 50
	go func() {
		var ids []int64
		for len(ids) < 2 {
			request, err := ptc.ReceiveRequest()
			if err != nil {
				return
			}
			id, _ := packetInt64At(request, 0)
			ids = append(ids, id)
		}
		for i := 0; i < count; i++ {
			_ = ptc.SendResponse(newIntermediateResponsePacket(ids[0], "1.2.3.1", []byte{'a', byte(i)}))
			_ = ptc.SendResponse(newIntermediateResponsePacket(ids[1], "1.2.3.1", []byte{'b', byte(i)}))
		}
		_ = ptc.SendResponse(newExtendedResponsePacket(ids[0], LDAPResultSuccess, "", nil))
		_ = ptc.SendResponse(newExtendedResponsePacket(ids[1], LDAPResultSuccess, "", nil))
	}()
	ctx := context.Background()
	ra := conn.ExtendedAsync(ctx, NewExtendedRequest(testExtendedAsyncOID, nil), 0)
	time.Sleep(20 * time.Millisecond) // a is sent first
	rb := conn.ExtendedAsync(ctx, NewExtendedRequest(testExtendedAsyncOID, nil), 0)

	// read all of b first while a is not read, then all of a
	for _, s := range []struct {
		tag byte
		r   ExtendedAsyncResponse
	}{{'b', rb}, {'a', ra}} {
		for i := 0; i < count; i++ {
			if !nextWithTimeout(t, s.r) {
				t.Fatalf("%c %d: %v", s.tag, i, s.r.Err())
			}
			if got := s.r.Intermediate().Value.Data.Bytes(); !bytes.Equal(got, []byte{s.tag, byte(i)}) {
				t.Fatalf("%c %d: got %x", s.tag, i, got)
			}
		}
		if nextWithTimeout(t, s.r) || s.r.Err() != nil {
			t.Fatalf("%c: end %v", s.tag, s.r.Err())
		}
	}
}
