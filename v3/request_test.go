package ldap

import (
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// buildReferralResponse builds a ModifyResponse envelope whose result code is a
// referral. When withURI is false the referral SEQUENCE is left empty, which is
// what a non-conforming or malicious server can send.
func buildReferralResponse(withURI bool) *ber.Packet {
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 2, "MessageID"))

	resp := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationModifyResponse, nil, "Modify Response")
	resp.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(LDAPResultReferral), "resultCode"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	resp.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "referral", "errorMessage"))

	referral := ber.Encode(ber.ClassContext, ber.TypeConstructed, ber.TagBitString, nil, "Referral")
	if withURI {
		referral.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.TagBitString, "ldap://ds.example.com/", "uri"))
	}
	resp.AppendChild(referral)

	envelope.AppendChild(resp)
	return envelope
}

func TestGetReferralEmptySequence(t *testing.T) {
	packet := buildReferralResponse(false)
	err := GetLDAPError(packet)
	if !IsErrorWithCode(err, LDAPResultReferral) {
		t.Fatalf("expected referral error, got %v", err)
	}

	// An empty referral SEQUENCE must not panic the caller.
	if got := getReferral(err, packet); got != "" {
		t.Errorf("expected empty referral, got %q", got)
	}
}

func TestGetReferralWithURI(t *testing.T) {
	packet := buildReferralResponse(true)
	err := GetLDAPError(packet)

	const want = "ldap://ds.example.com/"
	if got := getReferral(err, packet); got != want {
		t.Errorf("expected referral %q, got %q", want, got)
	}
}
