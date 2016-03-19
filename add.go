//
// https://tools.ietf.org/html/rfc4511
//
// AddRequest ::= [APPLICATION 8] SEQUENCE {
//      entry           LDAPDN,
//      attributes      AttributeList }
//
// AttributeList ::= SEQUENCE OF attribute Attribute

package ldap

import (
	"errors"
	"log"

	"gopkg.in/asn1-ber.v1"
)

type Attribute struct {
	AttrType string
	AttrVals []string
}

func (a *Attribute) encode() *ber.Packet {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
	seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.AttrType, "Type"))
	set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "AttributeValue")
	for _, value := range a.AttrVals {
		set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Vals"))
	}
	seq.AppendChild(set)
	return seq
}

type AddRequest struct {
	DN         string
	Attributes []Attribute
}

func (a AddRequest) encode() *ber.Packet {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationAddRequest, nil, "Add Request")
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.DN, "DN"))
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, attribute := range a.Attributes {
		attributes.AppendChild(attribute.encode())
	}
	request.AppendChild(attributes)
	return request
}

func (a *AddRequest) Attribute(attrType string, attrVals []string) {
	a.Attributes = append(a.Attributes, Attribute{AttrType: attrType, AttrVals: attrVals})
}

func NewAddRequest(dn string) *AddRequest {
	return &AddRequest{
		DN: dn,
	}

}

func (l *Conn) Add(addRequest *AddRequest) error {
	messageID := l.nextMessageID()
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	packet.AppendChild(addRequest.encode())

	l.Debug.PrintPacket(packet)

	channel, err := l.sendMessage(packet)
	if err != nil {
		return err
	}
	if channel == nil {
		return NewError(ErrorNetwork, errors.New("ldap: could not send message"))
	}
	defer l.finishMessage(messageID)

	l.Debug.Printf("%d: waiting for response", messageID)
	packet = <-channel
	l.Debug.Printf("%d: got response %p", messageID, packet)
	if packet == nil {
		return NewError(ErrorNetwork, errors.New("ldap: could not retrieve message"))
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return err
		}
		ber.PrintPacket(packet)
	}

	if packet.Children[1].Tag == ApplicationAddResponse {
		resultCode, resultDescription := getLDAPResultCode(packet)
		if resultCode != 0 {
			return NewError(resultCode, errors.New(resultDescription))
		}
	} else {
		log.Printf("Unexpected Response: %d", packet.Children[1].Tag)
	}

	l.Debug.Printf("%d: returning", messageID)
	return nil
}
