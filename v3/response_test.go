package ldap

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// TestSearchAsyncCancelUnblocksProducer reproduces a goroutine leak in the
// SearchAsync producer. The doc comment promises "To stop the search, call
// the cancel function of the context", but the producer only checked ctx while
// waiting for server packets: when the consumer stopped calling Next() with
// more undelivered results than the channel buffer holds, the producer
// blocked forever on the unguarded `r.ch <- result` send and never observed
// the cancellation, leaking the goroutine and the buffered entries.
func TestSearchAsyncCancelUnblocksProducer(t *testing.T) {
	ptc := newPacketTranslatorConn()
	defer func() { _ = ptc.Close() }()

	conn := NewConn(ptc, false)
	conn.Start()
	// If the producer regresses into a permanent block, a plain conn.Close()
	// deadlocks behind the leaked goroutine and hangs the whole test binary;
	// bound it so the failure stays diagnosable.
	defer runWithTimeout(t, time.Second, func() {
		_ = conn.Close()
	})

	// Server: read the search request and reply with more entries than the
	// result channel can buffer, without a SearchResultDone so the stream
	// only ends via cancellation.
	const numEntries = 6
	go func() {
		req, err := ptc.ReceiveRequest()
		if err != nil {
			// The conn is closed by a deferred cleanup, so this error can
			// surface after the test has completed, where t.Errorf panics.
			if err != errPacketTranslatorConnClosed {
				t.Errorf("unable to receive search request: %s", err)
			}
			return
		}
		msgID := req.Children[0].Value.(int64)
		for i := range numEntries {
			entry := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "Search Result Entry")
			entry.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, fmt.Sprintf("cn=user%d,dc=example,dc=com", i), "Object Name"))
			entry.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes"))

			response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
			response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, msgID, "MessageID"))
			response.AppendChild(entry)
			if err := ptc.SendResponse(response); err != nil {
				if err != errPacketTranslatorConnClosed {
					t.Errorf("unable to send search result entry: %s", err)
				}
				return
			}
		}
	}()

	searchRequest := NewSearchRequest(
		"dc=example,dc=com",
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		"(objectClass=*)",
		nil,
		nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := conn.SearchAsync(ctx, searchRequest, 1)

	// Consume a single entry, then abandon the iteration.
	if !r.Next() {
		t.Fatalf("expected an entry, got none: %v", r.Err())
	}

	// Wait until the producer has filled the buffer again and is therefore
	// blocked delivering the next result.
	ch := r.(*searchResponse).ch
	waitForCondition(t, 3*time.Second, "result channel buffer never filled up", func() bool {
		return len(ch) == cap(ch)
	})
	// A full buffer only implies the producer is about to block; give it a
	// moment to actually park on the next channel send so that cancellation
	// exercises the send path rather than the packet-wait select.
	time.Sleep(50 * time.Millisecond)

	cancel()

	// The producer goroutine must exit even though nobody drains the
	// remaining results.
	waitForCondition(t, 3*time.Second, "searchResponse producer goroutine is still running after context cancellation", func() bool {
		return !searchProducerRunning()
	})

	// With the producer gone the result channel is closed: Next drains the
	// few buffered results and then reports completion.
	runWithTimeout(t, time.Second, func() {
		for r.Next() {
		}
	})
}

// TestDecodeSearchResponseControls pins the controls handling of the search
// entry and done decoders: every control in the SEQUENCE OF Control is
// decoded, and an empty (valid) sequence is skipped instead of failing the
// search.
func TestDecodeSearchResponseControls(t *testing.T) {
	entryOp := func() *ber.Packet {
		op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "Search Result Entry")
		op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn=a", "Object Name"))
		attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
		attrs.AppendChild(newPartialAttribute("cn", "a"))
		op.AppendChild(attrs)
		return op
	}
	controlsElement := func(controls ...*ber.Packet) *ber.Packet {
		el := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
		for _, c := range controls {
			el.AppendChild(c)
		}
		return el
	}

	entryWithControls := newDecodeEnvelope(1, entryOp())
	entryWithControls.AppendChild(controlsElement(
		NewControlPaging(100).Encode(),
		NewControlManageDsaIT(true).Encode(),
	))
	result, err := decodeSearchResultEntry(entryWithControls)
	if err != nil {
		t.Fatalf("decodeSearchResultEntry: %v", err)
	}
	if len(result.Controls) != 2 {
		t.Fatalf("expected both controls decoded, got %d", len(result.Controls))
	}

	entryEmptyControls := newDecodeEnvelope(1, entryOp())
	entryEmptyControls.AppendChild(controlsElement())
	result, err = decodeSearchResultEntry(entryEmptyControls)
	if err != nil {
		t.Fatalf("empty controls must not fail the entry decode: %v", err)
	}
	if len(result.Controls) != 0 {
		t.Fatalf("expected no controls, got %d", len(result.Controls))
	}

	doneWithControls := newDecodeEnvelope(1, newResultProtocolOp(ApplicationSearchResultDone, 0))
	doneWithControls.AppendChild(controlsElement(
		NewControlPaging(100).Encode(),
		NewControlManageDsaIT(true).Encode(),
	))
	done, err := decodeSearchResultDone(doneWithControls)
	if err != nil {
		t.Fatalf("decodeSearchResultDone: %v", err)
	}
	if done == nil || len(done.Controls) != 2 {
		t.Fatalf("expected both done controls decoded, got %v", done)
	}

	doneEmptyControls := newDecodeEnvelope(1, newResultProtocolOp(ApplicationSearchResultDone, 0))
	doneEmptyControls.AppendChild(controlsElement())
	done, err = decodeSearchResultDone(doneEmptyControls)
	if err != nil {
		t.Fatalf("empty controls must not fail the done decode: %v", err)
	}
	if done != nil {
		t.Fatalf("expected no result for empty controls, got %v", done)
	}
}

// TestDecodeSearchResultEntryRequiresAttributes pins the RFC 4511 requirement
// shared with the Search decode path: the attributes element must be present
// even when empty, so a missing one is malformed rather than an empty entry.
func TestDecodeSearchResultEntryRequiresAttributes(t *testing.T) {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "Search Result Entry")
	op.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "cn=a", "Object Name"))

	result, err := decodeSearchResultEntry(newDecodeEnvelope(1, op))
	if err == nil {
		t.Fatalf("expected an error for a missing attributes element, got %v", result)
	}
	if !errors.Is(err, errMalformedPacket) {
		t.Fatalf("expected errMalformedPacket, got %v", err)
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(msg)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// searchProducerRunning reports whether a SearchAsync producer goroutine is
// alive by scanning all goroutine stacks. It is coupled to the method name:
// if (*searchResponse).start is ever renamed, this returns false vacuously
// and the leak assertion above loses its regression-catching power.
func searchProducerRunning() bool {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			return bytes.Contains(buf[:n], []byte("(*searchResponse).start"))
		}
		buf = make([]byte, 2*len(buf))
	}
}
