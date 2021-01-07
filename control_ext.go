package ldap

import (
	ber "github.com/go-asn1-ber/asn1-ber"
)

// ControlMicrosoftServerExtendedDnOid implements the control LDAP_SERVER_EXTENDED_DN_OID described in
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3c5e87db-4728-4f29-b164-01dd7d7391ea
type ControlMicrosoftServerExtendedDnOid struct {
	Critical bool
	Flag     int
}

// GetControlType returns the OID
func (c *ControlMicrosoftServerExtendedDnOid) GetControlType() string {
	return ControlTypeMicrosoftServerExtendedDnOid
}

// Encode returns the ber packet representation
func (c *ControlMicrosoftServerExtendedDnOid) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.GetControlType(), "Control Type ("+ControlTypeMap[ControlTypeMicrosoftServerExtendedDnOid]+")"))
	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.Critical, "Criticality"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Extend DN)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "ExtendDNRequestValue")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, c.Flag, "Flags"))
	p2.AppendChild(seq)
	packet.AppendChild(p2)

	return packet
}

func (c *ControlMicrosoftServerExtendedDnOid) String() string {
	return ControlTypeMap[ControlTypeMicrosoftServerExtendedDnOid] + " " + c.GetControlType()
}
