package gssapi

import (
	"encoding/asn1"
	"encoding/binary"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/asnAppTag"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
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

// apRepToken builds a KRB5 GSS-API token carrying an AP-REP whose encrypted
// part, sealed with key, echoes the given authenticator ctime and cusec.
func apRepToken(t *testing.T, key types.EncryptionKey, ctime time.Time, cusec int) []byte {
	t.Helper()
	part, err := asn1.Marshal(messages.EncAPRepPart{CTime: ctime, Cusec: cusec})
	if err != nil {
		t.Fatal(err)
	}
	encPart, err := crypto.GetEncryptedData(asn1tools.AddASNAppTag(part, asnAppTag.EncAPRepPart), key, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		t.Fatal(err)
	}
	rep, err := asn1.Marshal(messages.APRep{PVNO: 5, MsgType: msgtype.KRB_AP_REP, EncPart: encPart})
	if err != nil {
		t.Fatal(err)
	}
	b, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}) // KRB5 mechanism
	if err != nil {
		t.Fatal(err)
	}
	b = append(b, 0x02, 0x00) // AP-REP token ID
	b = append(b, asn1tools.AddASNAppTag(rep, asnAppTag.APREP)...)
	return asn1tools.AddASNAppTag(b, 0)
}

// An AP-REP recorded from an earlier bind under the same cached service ticket
// decrypts with the same session key, but does not echo this authenticator.
func TestInitSecContextRejectsStaleAPRep(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	ctime := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	c := &Client{ekey: key, ctime: ctime, cusec: 123}

	if _, _, err := c.InitSecContext("ldap/x", apRepToken(t, key, ctime.Add(-time.Hour), 123)); err == nil {
		t.Fatal("expected an AP-REP for another authenticator to be rejected")
	}
	if _, needContinue, err := c.InitSecContext("ldap/x", apRepToken(t, key, ctime, 123)); err != nil || needContinue {
		t.Fatalf("matching AP-REP: needContinue=%v err=%v", needContinue, err)
	}
}
