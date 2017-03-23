// This file contains the "Who Am I?" extended operation as specified in rfc 4532
//
// https://tools.ietf.org/html/rfc4532
//

package ldap

import (
	"errors"
	"fmt"

	"gopkg.in/asn1-ber.v1"
)

const (
	whoamiOID = "1.3.6.1.4.1.4203.1.11.3"
)

type WhoAmIRequest bool

type WhoAmIResult struct {
	AuthzId string
}

func (r WhoAmIRequest) encode() (*ber.Packet, error) {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "Who Am I? Extended Operation")
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, whoamiOID, "Extended Request Name: Who Am I? OID"))
	return request, nil
}

func (l *Conn) WhoAmI(controls []Control) (*WhoAmIResult, error) {
	messageID := l.nextMessageID()

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "MessageID"))
	req := WhoAmIRequest(true)
	encodedWhoAmIRequest, err := req.encode()
	if err != nil {
		return nil, err
	}
	packet.AppendChild(encodedWhoAmIRequest)

	if len(controls) != 0 {
		packet.AppendChild(encodeControls(controls))
	}

	l.Debug.PrintPacket(packet)

	channel, err := l.sendMessage(packet)
	if err != nil {
		return nil, err
	}
	if channel == nil {
		return nil, NewError(ErrorNetwork, errors.New("ldap: could not send message"))
	}
	defer l.finishMessage(messageID)

	result := &WhoAmIResult{}

	l.Debug.Printf("%d: waiting for response", messageID)
	packetResponse, ok := <-channel
	if !ok {
		return nil, NewError(ErrorNetwork, errors.New("ldap: channel closed"))
	}
	packet, err = packetResponse.ReadPacket()
	l.Debug.Printf("%d: got response %p", messageID, packet)
	if err != nil {
		return nil, err
	}

	if packet == nil {
		return nil, NewError(ErrorNetwork, errors.New("ldap: could not retrieve message"))
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		ber.PrintPacket(packet)
	}

	if packet.Children[1].Tag == ApplicationExtendedResponse {
		resultCode, resultDescription := getLDAPResultCode(packet)
		if resultCode != 0 {
			return nil, NewError(resultCode, errors.New(resultDescription))
		}
	} else {
		return nil, NewError(ErrorUnexpectedResponse, fmt.Errorf("Unexpected Response: %d", packet.Children[1].Tag))
	}

	extendedResponse := packet.Children[1]
	for _, child := range extendedResponse.Children {
		if child.Tag == 11 {
			result.AuthzId = ber.DecodeString(child.Data.Bytes())
		}
	}

	return result, nil
}
