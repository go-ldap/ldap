package ldap

import (
	"errors"
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// newTestEnvelope builds a small LDAP envelope-like SEQUENCE with the given
// children, used to exercise the structural accessors.
func newTestEnvelope(children ...*ber.Packet) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "envelope")
	for _, c := range children {
		p.AppendChild(c)
	}
	return p
}

func newTestString(s string) *ber.Packet {
	return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, s, "s")
}

func newTestInt(i int64) *ber.Packet {
	return ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, i, "i")
}

func newTestBool(b bool) *ber.Packet {
	return ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, b, "b")
}

func TestPacketChild(t *testing.T) {
	envelope := newTestEnvelope(newTestInt(1), newTestString("two"))

	t.Run("valid index returns child", func(t *testing.T) {
		child, err := packetChild(envelope, 1)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got, _ := packetString(child); got != "two" {
			t.Fatalf("expected %q, got %q", "two", got)
		}
	})

	t.Run("out of range", func(t *testing.T) {
		for _, i := range []int{-1, 2, 99} {
			_, err := packetChild(envelope, i)
			if err == nil {
				t.Fatalf("index %d: expected error, got nil", i)
			}
			if !errors.Is(err, ErrMalformedPacket) {
				t.Fatalf("index %d: expected ErrMalformedPacket, got %v", i, err)
			}
		}
	})

	t.Run("nil packet", func(t *testing.T) {
		_, err := packetChild(nil, 0)
		if !errors.Is(err, ErrMalformedPacket) {
			t.Fatalf("expected ErrMalformedPacket, got %v", err)
		}
	})

	t.Run("nil child", func(t *testing.T) {
		p := newTestEnvelope()
		p.Children = append(p.Children, nil)
		_, err := packetChild(p, 0)
		if !errors.Is(err, ErrMalformedPacket) {
			t.Fatalf("expected ErrMalformedPacket, got %v", err)
		}
	})
}

func TestPacketChildIfPresent(t *testing.T) {
	envelope := newTestEnvelope(newTestString("only"))

	child, ok, err := packetChildIfPresent(envelope, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok || child != nil {
		t.Fatalf("expected absent child, got ok=%v child=%v", ok, child)
	}

	child, ok, err = packetChildIfPresent(envelope, 0)
	if err != nil || !ok || child == nil {
		t.Fatalf("expected present child, got ok=%v child=%v err=%v", ok, child, err)
	}

	if _, _, err := packetChildIfPresent(nil, 0); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("expected ErrMalformedPacket for nil packet, got %v", err)
	}

	p := newTestEnvelope()
	p.Children = append(p.Children, nil)
	if _, _, err := packetChildIfPresent(p, 0); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("expected ErrMalformedPacket for nil child, got %v", err)
	}
}

func TestPacketLeafConversions(t *testing.T) {
	if s, err := packetString(newTestString("hello")); err != nil || s != "hello" {
		t.Fatalf("packetString: got %q, %v", s, err)
	}
	if i, err := packetInt64(newTestInt(42)); err != nil || i != 42 {
		t.Fatalf("packetInt64: got %d, %v", i, err)
	}
	if b, err := packetBool(newTestBool(true)); err != nil || !b {
		t.Fatalf("packetBool: got %v, %v", b, err)
	}

	// A field whose Value has the wrong Go type must produce a
	// malformed-packet error, never a panic.
	if _, err := packetString(newTestInt(1)); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("packetString(int): expected ErrMalformedPacket, got %v", err)
	}
	if _, err := packetInt64(newTestString("x")); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("packetInt64(string): expected ErrMalformedPacket, got %v", err)
	}
	if _, err := packetBool(newTestInt(1)); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("packetBool(int): expected ErrMalformedPacket, got %v", err)
	}
	if _, err := packetString(nil); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("packetString(nil): expected ErrMalformedPacket, got %v", err)
	}

	// A packet built without a data buffer must not panic on Data.Bytes().
	noData := &ber.Packet{Identifier: ber.Identifier{ClassType: ber.ClassUniversal, TagType: ber.TypePrimitive, Tag: ber.TagOctetString}}
	if _, err := packetData(noData); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("packetData(no data): expected ErrMalformedPacket, got %v", err)
	}
	if _, err := packetData(nil); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("packetData(nil): expected ErrMalformedPacket, got %v", err)
	}

	buf := newTestString("payload")
	data, err := packetData(buf)
	if err != nil {
		t.Fatalf("packetData: unexpected error: %v", err)
	}
	if string(data) != "payload" {
		t.Fatalf("packetData: expected %q, got %q", "payload", string(data))
	}
}

func TestPacketAtHelpers(t *testing.T) {
	envelope := newTestEnvelope(newTestString("dn"), newTestInt(7), newTestBool(false))

	if s, err := packetStringAt(envelope, 0); err != nil || s != "dn" {
		t.Fatalf("packetStringAt: got %q, %v", s, err)
	}
	if i, err := packetInt64At(envelope, 1); err != nil || i != 7 {
		t.Fatalf("packetInt64At: got %d, %v", i, err)
	}

	if _, err := packetStringAt(envelope, 99); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("out-of-range packetStringAt: expected ErrMalformedPacket, got %v", err)
	}
	if _, err := packetInt64At(envelope, 0); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("wrong-type packetInt64At: expected ErrMalformedPacket, got %v", err)
	}
	if _, err := packetDataAt(envelope, 0); err != nil {
		// child 0 is a string with a data buffer, so this should succeed.
		t.Fatalf("unexpected packetDataAt error: %v", err)
	}
}

func TestPacketChildCount(t *testing.T) {
	three := newTestEnvelope(newTestString("a"), newTestString("b"), newTestString("c"))

	t.Run("returns children when in range", func(t *testing.T) {
		children, err := packetChildCount(three, 1, 3, "control")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(children) != 3 {
			t.Fatalf("expected 3 children, got %d", len(children))
		}
	})

	t.Run("min violated", func(t *testing.T) {
		_, err := packetChildCount(three, 4, -1, "control")
		if !errors.Is(err, ErrMalformedPacket) {
			t.Fatalf("expected ErrMalformedPacket, got %v", err)
		}
		if !strings.Contains(err.Error(), "expected 4 or more children, got 3") {
			t.Fatalf("unexpected message: %v", err)
		}
	})

	t.Run("max violated", func(t *testing.T) {
		_, err := packetChildCount(three, -1, 2, "control")
		if !errors.Is(err, ErrMalformedPacket) {
			t.Fatalf("expected ErrMalformedPacket, got %v", err)
		}
		if !strings.Contains(err.Error(), "expected at most 2 children, got 3") {
			t.Fatalf("unexpected message: %v", err)
		}
	})

	t.Run("exact count satisfied", func(t *testing.T) {
		if _, err := packetChildCount(three, 3, 3, "control"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("exact count violated", func(t *testing.T) {
		_, err := packetChildCount(three, 2, 2, "control")
		if !errors.Is(err, ErrMalformedPacket) {
			t.Fatalf("expected ErrMalformedPacket, got %v", err)
		}
		if !strings.Contains(err.Error(), "expected 2 children, got 3") {
			t.Fatalf("unexpected message: %v", err)
		}
	})

	t.Run("nil packet", func(t *testing.T) {
		_, err := packetChildCount(nil, 1, 3, "control")
		if !errors.Is(err, ErrMalformedPacket) {
			t.Fatalf("expected ErrMalformedPacket, got %v", err)
		}
	})
}

// TestMalformedfIsLDAPError verifies that structural decode failures carry an
// LDAP result code while remaining matchable against the sentinel cause.
func TestMalformedfIsLDAPError(t *testing.T) {
	err := malformedf("child index %d out of range", 5)
	if !IsErrorWithCode(err, ErrorMalformedPacket) {
		t.Fatalf("expected ErrorMalformedPacket code, got %v", err)
	}
	if !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("expected ErrMalformedPacket sentinel, got %v", err)
	}
	if !strings.Contains(err.Error(), "child index 5 out of range") {
		t.Fatalf("unexpected message: %v", err)
	}
}
