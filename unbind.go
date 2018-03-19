package ldap

import (
	"errors"

	"gopkg.in/asn1-ber.v1"
)

// Unbind performs an unbind waiting for conenciton closing
func (l *Conn) Unbind() error {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))
	unbindRequest := ber.Encode(ber.ClassApplication, ber.TypePrimitive, ApplicationUnbindRequest, nil, "Unbind Request")

	packet.AppendChild(unbindRequest)

	if l.Debug {
		ber.PrintPacket(packet)
	}

	msgCtx, err := l.sendMessage(packet)
	if err != nil {
		return err
	}
	defer l.finishMessage(msgCtx)

	// No response expected,so close everything
	_, ok := <-msgCtx.responses
	if !ok {
		return NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
	}

	return nil
}
