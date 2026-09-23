package ldap

import (
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// fuzzDecodePackets decodes data into a BER packet, skipping inputs the BER
// decoder itself rejects.
func fuzzDecodePackets(data []byte) (*ber.Packet, bool) {
	packet, err := ber.ReadPacket(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	return packet, true
}

// FuzzDecodeControl exercises the control decoder, where hostile servers have
// historically triggered panics through nil control values, short value
// sequences and unexpected value types.
func FuzzDecodeControl(f *testing.F) {
	seeds := [][]byte{
		newTestEnvelope(newTestString("1.2.3.4.5"), newTestBool(true), newTestString("v")).Bytes(),
		newTestEnvelope(newTestString("1.2.3.4.5"), newTestString("v")).Bytes(),
		newTestEnvelope(newTestString("1.2.3.4.5")).Bytes(),
		newTestEnvelope().Bytes(),
		NewControlPaging(100).Encode().Bytes(),
		NewControlManageDsaIT(true).Encode().Bytes(),
		NewRequestControlDirSync(1, 2, []byte("cookie")).Encode().Bytes(),
		NewControlSyncRequest(SyncRequestModeRefreshOnly, []byte("cookie"), false).Encode().Bytes(),
		NewControlBeheraPasswordPolicy().Encode().Bytes(),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		packet, ok := fuzzDecodePackets(data)
		if !ok {
			return
		}
		_, _ = DecodeControl(packet)
	})
}

// FuzzGetLDAPErrorPacket exercises the LDAPResult decoder over arbitrary
// packets (complementing FuzzGetLDAPError, which only fuzzes the raw bytes).
func FuzzGetLDAPErrorPacket(f *testing.F) {
	seeds := [][]byte{
		newDecodeEnvelope(1, newResultProtocolOp(ApplicationModifyResponse, 0)).Bytes(),
		newDecodeEnvelope(1, newResultProtocolOp(ApplicationModifyResponse, 1)).Bytes(),
		newDecodeEnvelope(1, newResultProtocolOp(ApplicationBindResponse, 14)).Bytes(),
		newTestEnvelope().Bytes(),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		packet, ok := fuzzDecodePackets(data)
		if !ok {
			return
		}
		_ = GetLDAPError(packet)
	})
}

// FuzzUnpackAttributes exercises the PartialAttribute decoder used by search
// result entries.
func FuzzUnpackAttributes(f *testing.F) {
	partialAttribute := func(name string, values ...string) *ber.Packet {
		attr := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "PartialAttribute")
		attr.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, name, "type"))
		vals := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "vals")
		for _, v := range values {
			vals.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "value"))
		}
		attr.AppendChild(vals)
		return attr
	}
	attributesSequence := func(attrs ...*ber.Packet) []byte {
		seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
		for _, a := range attrs {
			seq.AppendChild(a)
		}
		return seq.Bytes()
	}

	seeds := [][]byte{
		attributesSequence(partialAttribute("cn", "a", "b")),
		attributesSequence(partialAttribute("cn")),
		attributesSequence(),
		newTestEnvelope().Bytes(),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		packet, ok := fuzzDecodePackets(data)
		if !ok {
			return
		}
		_, _ = unpackAttributes(packet.Children)
	})
}

// FuzzAddLDAPDescriptions exercises the debug decorator, which performs the
// same structural traversal as the real decoders.
func FuzzAddLDAPDescriptions(f *testing.F) {
	seeds := [][]byte{
		newDecodeEnvelope(1, newResultProtocolOp(ApplicationSearchResultDone, 0)).Bytes(),
		newDecodeEnvelope(1, newResultProtocolOp(ApplicationBindResponse, 0)).Bytes(),
		newDecodeEnvelope(1, ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationSearchResultEntry, nil, "Search Result Entry")).Bytes(),
		newTestEnvelope().Bytes(),
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		packet, ok := fuzzDecodePackets(data)
		if !ok {
			return
		}
		_ = addLDAPDescriptions(packet)
	})
}
