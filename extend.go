package ldap

import (
	"fmt"
	ber "github.com/go-asn1-ber/asn1-ber"
)

// ExtendedRequest TODO
// See: https://www.rfc-editor.org/rfc/rfc4511#section-4.12
type ExtendedRequest struct {
	Name  string
	Value string
}

func NewExtendedRequest(name, value string) *ExtendedRequest {
	return &ExtendedRequest{
		Name:  name,
		Value: value,
	}
}

func (er ExtendedRequest) appendTo(envelope *ber.Packet) error {
	// ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
	// 	requestName      [0] LDAPOID,
	// 	requestValue     [1] OCTET STRING OPTIONAL }
	//
	// Despite the RFC documentation stating otherwise, the requestName field needs to be
	// of class application and type EOC, otherwise the directory server will terminate
	// the connection right away (tested against OpenLDAP, Active Directory).
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "Extended Request")
	pkt.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.TagEOC, er.Name, "Extension Name"))
	if er.Value != "" {
		pkt.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, ber.TagEOC, er.Value, "Extension Value"))
	}
	envelope.AppendChild(pkt)
	return nil
}

type ExtendResponse struct {
	Name  string
	Value string
}

func (l *Conn) Extended(er *ExtendedRequest) (*ExtendResponse, error) {
	msgCtx, err := l.doRequest(er)
	if err != nil {
		return nil, err
	}
	defer l.finishMessage(msgCtx)

	// ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
	//   COMPONENTS OF LDAPResult,
	//   responseName     [10] LDAPOID OPTIONAL,
	//   responseValue    [11] OCTET STRING OPTIONAL }
	packet, err := l.readPacket(msgCtx)
	if err != nil {
		return nil, err
	}
	if len(packet.Children) < 2 || len(packet.Children[1].Children) < 4 {
		return nil, fmt.Errorf(
			"ldap: malformed extended response: expected 4 children, got %d",
			len(packet.Children),
		)
	}

	response := new(ExtendResponse)
	response.Name = packet.Children[1].Children[3].Data.String()
	if len(packet.Children) == 4 {
		response.Value = packet.Children[1].Children[4].Data.String()
	}

	return response, nil
}
