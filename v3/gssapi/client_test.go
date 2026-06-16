package gssapi

import (
	"encoding/binary"
	"testing"

	"github.com/jcmturner/gokrb5/v8/gssapi"
)

// wrapTokenHeader builds a valid 16-byte acceptor WrapToken header with the
// given checksum length (EC) field.
func wrapTokenHeader(checksumLen uint16) []byte {
	h := make([]byte, gssapi.HdrLen)
	h[0], h[1] = 0x05, 0x04 // token id
	h[2] = 0x01             // acceptor flag set
	h[3] = gssapi.FillerByte
	binary.BigEndian.PutUint16(h[4:6], checksumLen)
	return h
}

// A malicious server can set the checksum-length field high enough that
// 16 + checksumL overflows uint16. The sanity check still passes because the
// token is large, so the bad offset reached the slice operations.
func TestUnmarshalWrapTokenChecksumLengthOverflow(t *testing.T) {
	const checksumLen = uint16(0xFFFF)
	b := wrapTokenHeader(checksumLen)
	// Pad so len(b)-HdrLen >= checksumLen and the sanity check is satisfied.
	b = append(b, make([]byte, int(checksumLen))...)

	wt := &gssapi.WrapToken{}
	if err := UnmarshalWrapToken(wt, b, true); err != nil {
		t.Logf("got expected error: %v", err)
	}
}

func TestUnmarshalWrapTokenSplit(t *testing.T) {
	checksum := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	payload := []byte("payload")

	b := wrapTokenHeader(uint16(len(checksum)))
	b = append(b, checksum...)
	b = append(b, payload...)

	wt := &gssapi.WrapToken{}
	if err := UnmarshalWrapToken(wt, b, true); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(wt.CheckSum) != string(checksum) {
		t.Errorf("checksum: got %x, want %x", wt.CheckSum, checksum)
	}
	if string(wt.Payload) != string(payload) {
		t.Errorf("payload: got %q, want %q", wt.Payload, payload)
	}
}
