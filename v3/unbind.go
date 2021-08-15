package ldap

import (
	ber "github.com/go-asn1-ber/asn1-ber"
	"net"
)

type unbindRequest struct{}

var _unbindRequest = unbindRequest{}

func (unbindRequest) appendTo(envelope *ber.Packet) error {
	envelope.AppendChild(ber.Encode(ber.ClassApplication, ber.TypePrimitive, ApplicationUnbindRequest, nil, "Unbind Request"))
	return nil
}

// Unbind will perform a unbind request. The Unbind operation
// should be thought of as the "quit" operation.
// See https://datatracker.ietf.org/doc/html/rfc4511#section-4.3
func (l *Conn) Unbind() error {
	if l.conn == nil || l.IsClosing() {
		return net.ErrClosed
	}

	_, err := l.doRequest(_unbindRequest)
	if err != nil {
		return err
	}

	// Since an unbindRequest does not send an response, we need
	// another factor to determine whether the message has been
	// sent or is still in the channel waiting ...
	//
	// Sending an unbindRequest will make the connection unusable anyways.
	// Pending requests will fail with:
	// LDAP Result Code 200 "Network Error": ldap: response channel closed
	l.Close()

	return nil
}
