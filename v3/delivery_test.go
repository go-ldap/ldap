package ldap

import (
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const testDeliveryOID = "1.3.6.1.4.1.99999.2"

// newSearchResultEntryPacket builds an LDAPMessage carrying a SearchResultEntry
// with no attributes.
func newSearchResultEntryPacket(msgID int64, dn string) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "Search Result Entry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "objectName"))
	op.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "attributes"))
	return newDecodeEnvelope(msgID, op)
}

// newExtendedResponsePacket builds an LDAPMessage carrying an ExtendedResponse.
func newExtendedResponsePacket(msgID int64, resultCode int64, name string, value []byte) *ber.Packet {
	var extra []*ber.Packet
	if name != "" {
		extra = append(extra, ber.NewString(ber.ClassContext, ber.TypePrimitive, 10, name, "responseName"))
	}
	if value != nil {
		extra = append(extra, ber.NewString(ber.ClassContext, ber.TypePrimitive, 11, string(value), "responseValue"))
	}
	return newDecodeEnvelope(msgID, newResultProtocolOp(ApplicationExtendedResponse, resultCode, extra...))
}

func newSearchDonePacket(msgID int64) *ber.Packet {
	return newDecodeEnvelope(msgID, newResultProtocolOp(ApplicationSearchResultDone, LDAPResultSuccess))
}

func testSearchRequest() *SearchRequest {
	return NewSearchRequest("dc=example,dc=com", ScopeWholeSubtree, NeverDerefAliases, 0, 0, false, "(objectClass=*)", nil, nil)
}

func startDeliveryConn(t *testing.T) (*Conn, *packetTranslatorConn) {
	t.Helper()
	ptc := newPacketTranslatorConn()
	conn := NewConn(ptc, false)
	conn.Start()
	t.Cleanup(func() { _ = ptc.Close(); _ = conn.Close() })
	return conn, ptc
}

// slowConsumerServer answers the first request with `count` messages built by
// stream and never ends it; every following request (an extended request) gets
// a successful ExtendedResponse.
func slowConsumerServer(ptc *packetTranslatorConn, count int, stream func(msgID int64, i int) *ber.Packet) {
	go func() {
		first := true
		for {
			request, err := ptc.ReceiveRequest()
			if err != nil {
				return
			}
			msgID, err := packetInt64At(request, 0)
			if err != nil {
				return
			}
			if first {
				first = false
				for i := 0; i < count; i++ {
					if ptc.SendResponse(stream(msgID, i)) != nil {
						return
					}
				}
				continue
			}
			_ = ptc.SendResponse(newExtendedResponsePacket(msgID, LDAPResultSuccess, "", nil))
		}
	}()
}

// requireOtherRequestCompletes runs an Extended request on conn while the
// stream of a previous request is not being consumed, and fails if it does not
// complete: a slow consumer must not block the other requests of the
// connection.
func requireOtherRequestCompletes(t *testing.T, conn *Conn) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := conn.Extended(NewExtendedRequest(testDeliveryOID, nil))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second request: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the connection is blocked by the unconsumed responses of another request")
	}
}

// searchNextWithTimeout calls r.Next and fails the test if it blocks too long.
func searchNextWithTimeout(t *testing.T, r Response) bool {
	t.Helper()
	result := make(chan bool, 1)
	go func() { result <- r.Next() }()
	select {
	case ok := <-result:
		return ok
	case <-time.After(5 * time.Second):
		t.Fatal("Response.Next blocked")
		return false
	}
}

func TestSearchAsyncSlowConsumerDoesNotBlockConnection(t *testing.T) {
	conn, ptc := startDeliveryConn(t)
	const count = 10
	slowConsumerServer(ptc, count, func(msgID int64, i int) *ber.Packet {
		return newSearchResultEntryPacket(msgID, fmt.Sprintf("cn=%d,dc=example,dc=com", i))
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := conn.SearchAsync(ctx, testSearchRequest(), 1)
	time.Sleep(200 * time.Millisecond) // let the entries arrive while nobody calls Next

	requireOtherRequestCompletes(t, conn)

	// the entries were queued, not lost
	for i := 0; i < count; i++ {
		if !searchNextWithTimeout(t, r) {
			t.Fatalf("entry %d: %v", i, r.Err())
		}
		if want := fmt.Sprintf("cn=%d,dc=example,dc=com", i); r.Entry().DN != want {
			t.Fatalf("entry %d: %s, want %s", i, r.Entry().DN, want)
		}
	}
}

// TestInterleavedSearchAsyncOnOneConnection runs two searches on the same
// connection, with interleaved responses: each one receives its own entries, in
// order, while the other is not being read.
func TestInterleavedSearchAsyncOnOneConnection(t *testing.T) {
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
			_ = ptc.SendResponse(newSearchResultEntryPacket(ids[0], fmt.Sprintf("cn=a%d", i)))
			_ = ptc.SendResponse(newSearchResultEntryPacket(ids[1], fmt.Sprintf("cn=b%d", i)))
		}
		_ = ptc.SendResponse(newSearchDonePacket(ids[0]))
		_ = ptc.SendResponse(newSearchDonePacket(ids[1]))
	}()
	ctx := context.Background()
	ra := conn.SearchAsync(ctx, testSearchRequest(), 0)
	time.Sleep(20 * time.Millisecond) // a is sent first
	rb := conn.SearchAsync(ctx, testSearchRequest(), 0)

	// read all of b first while a is not read, then all of a
	for _, s := range []struct {
		prefix string
		r      Response
	}{{"b", rb}, {"a", ra}} {
		for i := 0; i < count; i++ {
			if !searchNextWithTimeout(t, s.r) {
				t.Fatalf("%s %d: %v", s.prefix, i, s.r.Err())
			}
			if want := fmt.Sprintf("cn=%s%d", s.prefix, i); s.r.Entry().DN != want {
				t.Fatalf("got %s, want %s", s.r.Entry().DN, want)
			}
		}
		if searchNextWithTimeout(t, s.r) || s.r.Err() != nil {
			t.Fatalf("%s: end %v", s.prefix, s.r.Err())
		}
	}
}

// TestMessageContextForwardersExit checks that the per-request forwarder
// goroutines end with their request, also when the connection is closed while
// responses are still queued.
func TestMessageContextForwardersExit(t *testing.T) {
	ptc := newPacketTranslatorConn()
	conn := NewConn(ptc, false)
	conn.Start()
	go func() {
		first := true
		for {
			request, err := ptc.ReceiveRequest()
			if err != nil {
				return
			}
			msgID, _ := packetInt64At(request, 0)
			op, _ := packetChild(request, 1)
			if op != nil && op.Tag == ApplicationSearchRequest && first {
				first = false // the search stream: entries never read, never ended
				for i := 0; i < 10; i++ {
					_ = ptc.SendResponse(newSearchResultEntryPacket(msgID, fmt.Sprintf("cn=%d", i)))
				}
				continue
			}
			_ = ptc.SendResponse(newExtendedResponsePacket(msgID, LDAPResultSuccess, "", nil))
		}
	}()
	before := runtime.NumGoroutine()
	for i := 0; i < 200; i++ {
		if _, err := conn.Extended(NewExtendedRequest(testDeliveryOID, nil)); err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
	}
	waitGoroutines(t, before)

	// responses queued and never read, then the connection is closed
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_ = conn.SearchAsync(ctx, testSearchRequest(), 1)
	time.Sleep(50 * time.Millisecond)
	_ = conn.Close()
	_ = ptc.Close()
	cancel()
	waitGoroutines(t, before-3) // reader, processMessages and the fake server are gone too
}

func waitGoroutines(t *testing.T, limit int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > limit {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines, expected at most %d: forwarders leaked", runtime.NumGoroutine(), limit)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
