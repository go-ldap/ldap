package ldap

import (
	"errors"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// errMalformedPacket is the sentinel wrapped by every structural decoding
// failure reported by the helpers in this file. It is nested inside the
// LDAP-style *Error returned by malformedf, so callers can match either with
// errors.Is: the *Error for the LDAP result code, or this sentinel for the
// specific malformed-packet cause.
var errMalformedPacket = errors.New("ldap: malformed packet")

// malformedf builds an LDAP-style error (NewError with ErrorMalformedPacket)
// wrapping errMalformedPacket, so every structural decode failure is
// descriptive, carries an LDAP result code, and remains matchable with
// errors.Is.
func malformedf(format string, args ...any) error {
	return NewError(ErrorMalformedPacket, fmt.Errorf("%w: %s", errMalformedPacket, fmt.Sprintf(format, args...)))
}

// packetChildren returns the children of p. The result is only meaningful for
// the ordered, schema-directed accessors below; callers that already know the
// expected count should prefer packetChild.
func packetChildren(p *ber.Packet) ([]*ber.Packet, error) {
	if p == nil {
		return nil, malformedf("nil packet")
	}
	return p.Children, nil
}

// packetChildCount asserts that p has between min and max direct children
// (inclusive) and returns them. A negative min disables the lower bound and a
// negative max disables the upper bound. It centralizes the repeated
// children-count validation so every decode path rejects malformed packets
// with a consistent, descriptive error instead of a bespoke length check.
//
// min == max means an exact count is required.
func packetChildCount(p *ber.Packet, min, max int, what string) ([]*ber.Packet, error) {
	if p == nil {
		return nil, malformedf("%s is missing", what)
	}
	n := len(p.Children)
	switch {
	case min >= 0 && max >= 0 && min == max && n != min:
		return nil, malformedf("%s: expected %d children, got %d", what, min, n)
	case min >= 0 && n < min:
		return nil, malformedf("%s: expected %d or more children, got %d", what, min, n)
	case max >= 0 && n > max:
		return nil, malformedf("%s: expected at most %d children, got %d", what, max, n)
	}
	return p.Children, nil
}

// packetChild returns the i-th child of p. It is the primary accessor for
// inbound packets: a field's position in its ASN.1 SEQUENCE is fixed by the
// relevant RFC, so callers must address packets by order rather than by
// inspecting the Go type of a child's Value.
func packetChild(p *ber.Packet, i int) (*ber.Packet, error) {
	if p == nil {
		return nil, malformedf("nil packet")
	}
	if i < 0 || i >= len(p.Children) {
		return nil, malformedf("child index %d out of range, packet has %d children", i, len(p.Children))
	}
	child := p.Children[i]
	if child == nil {
		return nil, malformedf("child index %d is nil", i)
	}
	return child, nil
}

// packetChildIfPresent is packetChild for OPTIONAL members: when the packet
// has no child at index i it reports ok == false instead of an error. A nil
// packet or a nil placeholder child is still an error, because those are
// invalid rather than simply absent.
func packetChildIfPresent(p *ber.Packet, i int) (child *ber.Packet, ok bool, err error) {
	if p == nil {
		return nil, false, malformedf("nil packet")
	}
	if i < 0 || i >= len(p.Children) {
		return nil, false, nil
	}
	child = p.Children[i]
	if child == nil {
		return nil, false, malformedf("child index %d is nil", i)
	}
	return child, true, nil
}

// packetChildrenByTag returns the direct children of p matching the given
// class and tag. It is used where order alone cannot identify a member, for
// example OPTIONAL or repeated elements whose presence is encoded by their
// tag; the decision is still structural (class/tag), never based on the Go
// type of Value.
func packetChildrenByTag(p *ber.Packet, classType ber.Class, tag ber.Tag) ([]*ber.Packet, error) {
	if p == nil {
		return nil, malformedf("nil packet")
	}
	var matches []*ber.Packet
	for _, child := range p.Children {
		if child == nil {
			continue
		}
		if child.ClassType == classType && child.Tag == tag {
			matches = append(matches, child)
		}
	}
	return matches, nil
}

// packetChildByTag returns the first direct child of p matching the given
// class and tag, reporting ok == false when no such child exists.
func packetChildByTag(p *ber.Packet, classType ber.Class, tag ber.Tag) (child *ber.Packet, ok bool, err error) {
	children, err := packetChildrenByTag(p, classType, tag)
	if err != nil {
		return nil, false, err
	}
	if len(children) == 0 {
		return nil, false, nil
	}
	return children[0], true, nil
}

// packetRequired returns p when it is non-nil and otherwise reports a
// malformed packet naming the mandatory element. It is used for control and
// response members whose value the schema requires.
func packetRequired(p *ber.Packet, what string) (*ber.Packet, error) {
	if p == nil {
		return nil, malformedf("%s is missing", what)
	}
	return p, nil
}

// packetString returns the string value of p. The field's position or tag is
// expected to have already fixed it as a string by the schema; this is the
// single guarded leaf conversion, never a way to discover what a field is.
func packetString(p *ber.Packet) (string, error) {
	if p == nil {
		return "", malformedf("missing string value")
	}
	s, ok := p.Value.(string)
	if !ok {
		return "", malformedf("expected string value, got %T", p.Value)
	}
	return s, nil
}

// packetInt64 returns the int64 value of p, whose schema position fixed it as
// an INTEGER or ENUMERATED.
func packetInt64(p *ber.Packet) (int64, error) {
	if p == nil {
		return 0, malformedf("missing integer value")
	}
	i, ok := p.Value.(int64)
	if !ok {
		return 0, malformedf("expected integer value, got %T", p.Value)
	}
	return i, nil
}

// packetBool returns the bool value of p, whose schema position or BOOLEAN tag
// fixed it as a boolean.
func packetBool(p *ber.Packet) (bool, error) {
	if p == nil {
		return false, malformedf("missing boolean value")
	}
	b, ok := p.Value.(bool)
	if !ok {
		return false, malformedf("expected boolean value, got %T", p.Value)
	}
	return b, nil
}

// packetData returns the raw BER contents of p. Unlike p.Data.Bytes() it is
// nil-safe, so a packet that carries no data buffer yields an error rather
// than a nil-pointer panic.
func packetData(p *ber.Packet) ([]byte, error) {
	if p == nil {
		return nil, malformedf("missing packet data")
	}
	if p.Data == nil {
		return nil, malformedf("packet has no data buffer")
	}
	return p.Data.Bytes(), nil
}

// packetStringAt returns the string value of the i-th child of p. It combines
// ordered access with the guarded leaf conversion and is the common shape for
// response fields such as a DN or a referral URI.
func packetStringAt(p *ber.Packet, i int) (string, error) {
	child, err := packetChild(p, i)
	if err != nil {
		return "", err
	}
	return packetString(child)
}

// packetInt64At returns the int64 value of the i-th child of p.
func packetInt64At(p *ber.Packet, i int) (int64, error) {
	child, err := packetChild(p, i)
	if err != nil {
		return 0, err
	}
	return packetInt64(child)
}

// packetDataAt returns the raw BER contents of the i-th child of p.
func packetDataAt(p *ber.Packet, i int) ([]byte, error) {
	child, err := packetChild(p, i)
	if err != nil {
		return nil, err
	}
	return packetData(child)
}

// packetBoolAt returns the bool value of the i-th child of p.
func packetBoolAt(p *ber.Packet, i int) (bool, error) {
	child, err := packetChild(p, i)
	if err != nil {
		return false, err
	}
	return packetBool(child)
}
