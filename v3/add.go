package ldap

import (
	"errors"
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// Attribute represents an LDAP attribute
type Attribute struct {
	// Type is the name of the LDAP attribute
	Type string
	// Vals are the LDAP attribute values
	Vals []string
}

func (a *Attribute) encode() *ber.Packet {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
	seq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, a.Type, "Type"))
	set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "AttributeValue")
	for _, value := range a.Vals {
		set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "Vals"))
	}
	seq.AppendChild(set)
	return seq
}

// AddRequest represents an LDAP AddRequest operation
type AddRequest struct {
	// DN identifies the entry being added
	DN string
	// Attributes list the attributes of the new entry
	Attributes []Attribute
	// Controls hold optional controls to send with the request
	Controls []Control
}

func (req *AddRequest) appendTo(envelope *ber.Packet) error {
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationAddRequest, nil, "Add Request")
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.DN, "DN"))
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	for _, attribute := range req.Attributes {
		attributes.AppendChild(attribute.encode())
	}
	pkt.AppendChild(attributes)

	envelope.AppendChild(pkt)
	if len(req.Controls) > 0 {
		envelope.AppendChild(encodeControls(req.Controls))
	}

	return nil
}

// Attribute adds an attribute with the given type and values
func (req *AddRequest) Attribute(attrType string, attrVals []string) {
	req.Attributes = append(req.Attributes, Attribute{Type: attrType, Vals: attrVals})
}

// NewAddRequest returns an AddRequest for the given DN, with no attributes
func NewAddRequest(dn string, controls []Control) *AddRequest {
	return &AddRequest{
		DN:       dn,
		Controls: controls,
	}
}

// Add performs the given AddRequest
func (l *Conn) Add(addRequest *AddRequest) error {
	if addRequest == nil {
		return NewError(ErrorNetwork, errors.New("AddRequest cannot be nil"))
	}

	msgCtx, err := l.doRequest(addRequest)
	if err != nil {
		return err
	}
	defer l.finishMessage(msgCtx)

	packet, err := l.readPacket(msgCtx)
	if err != nil {
		return err
	}

	protocolOp, err := packetChild(packet, 1)
	if err != nil {
		return err
	}
	if protocolOp.Tag == ApplicationAddResponse {
		if err := GetLDAPError(packet); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("ldap: unexpected response: %d", protocolOp.Tag)
	}
	return nil
}

// AddResult holds the server's response to an add request
type AddResult struct {
	// Controls are the returned controls
	Controls []Control
	// Referral is the returned referral
	Referral string
}

// AddWithResult performs the given AddRequest and returns the result
func (l *Conn) AddWithResult(addRequest *AddRequest) (*AddResult, error) {
	if addRequest == nil {
		return nil, NewError(ErrorNetwork, errors.New("AddRequest cannot be nil"))
	}

	msgCtx, err := l.doRequest(addRequest)
	if err != nil {
		return nil, err
	}
	defer l.finishMessage(msgCtx)

	result := &AddResult{
		Controls: make([]Control, 0),
	}

	l.Debug.Printf("%d: waiting for response", msgCtx.id)
	packet, err := l.readPacket(msgCtx)
	if err != nil {
		return nil, err
	}

	protocolOp, err := packetChild(packet, 1)
	if err != nil {
		return nil, err
	}
	if protocolOp.Tag == ApplicationAddResponse {
		if err = GetLDAPError(packet); err != nil {
			result.Referral = getReferral(err, packet)

			return result, err
		}
		controls, ok, err := packetChildIfPresent(packet, 2)
		if err != nil {
			return nil, err
		}
		if ok {
			for _, child := range controls.Children {
				decodedChild, err := DecodeControl(child)
				if err != nil {
					return nil, errors.New("failed to decode child control: " + err.Error())
				}
				result.Controls = append(result.Controls, decodedChild)
			}
		}
	} else {
		return nil, fmt.Errorf("ldap: unexpected response: %d", protocolOp.Tag)
	}
	l.Debug.Printf("%d: returning", msgCtx.id)
	return result, nil
}
