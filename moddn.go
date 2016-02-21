// File contains ModifyDN functionality
//
// https://tools.ietf.org/html/rfc4511
// ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
//      entry           LDAPDN,
//      newrdn          RelativeLDAPDN,
//      deleteoldrdn    BOOLEAN,
//      newSuperior     [0] LDAPDN OPTIONAL }
//
//
package ldap

import (
	"errors"
	"log"

	"gopkg.in/asn1-ber.v1"
)

type ModifyDNRequest struct {
	DN           string
	NewRDN       string
	DeleteOldRDN bool
	NewSuperior  string
}

// set "newSup" to empty string for just renaming, to move w/o renaming the "rdn" must be the first
// RDN of the given DN
func NewModifyDNRequest(dn string, rdn string, delOld bool, newSup string) *ModifyDNRequest {
	return &ModifyDNRequest{
		DN:           dn,
		NewRDN:       rdn,
		DeleteOldRDN: delOld,
		NewSuperior:  newSup,
	}
}

func (m ModifyDNRequest) encode() *ber.Packet {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationModifyDNRequest, nil, "Modify DN Request")
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, m.DN, "DN"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, m.NewRDN, "New RDN"))
	request.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, m.DeleteOldRDN, "Delete old RDN"))
	if m.NewSuperior != "" {
		// FIXME: do we need ber.TagEOC here or the context number? (in this case both are 0) ... and this
		// moves the DN to the new base on OpenLDAP ;-)
		request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, m.NewSuperior, "New Superior"))
	}
	return request
}

// Rename the given DN and optionally move to another base (when the "newSup" argument
// to NewModifyDNRequest() is not "").
func (l *Conn) ModifyDN(m *ModifyDNRequest) error {
	messageID := l.nextMessageID()
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	packet.AppendChild(m.encode())

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

	if packet.Children[1].Tag == ApplicationModifyDNResponse {
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

// vim: ts=4 sw=4 noexpandtab nolist
