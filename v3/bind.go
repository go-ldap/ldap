package ldap

import (
	"errors"
	"fmt"
	"io/ioutil"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// SimpleBindRequest represents a username/password bind operation
type SimpleBindRequest struct {
	// Username is the name of the Directory object that the client wishes to bind as
	Username string
	// Password is the credentials to bind with
	Password string
	// Controls are optional controls to send with the bind request
	Controls []Control
	// AllowEmptyPassword sets whether the client allows binding with an empty password
	// (normally used for unauthenticated bind).
	AllowEmptyPassword bool
}

// SimpleBindResult contains the response from the server
type SimpleBindResult struct {
	Controls []Control
}

// NewSimpleBindRequest returns a bind request
func NewSimpleBindRequest(username string, password string, controls []Control) *SimpleBindRequest {
	return &SimpleBindRequest{
		Username:           username,
		Password:           password,
		Controls:           controls,
		AllowEmptyPassword: false,
	}
}

func (req *SimpleBindRequest) appendTo(envelope *ber.Packet) error {
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, req.Username, "User Name"))
	pkt.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, req.Password, "Password"))

	envelope.AppendChild(pkt)
	if len(req.Controls) > 0 {
		envelope.AppendChild(encodeControls(req.Controls))
	}

	return nil
}

// SimpleBind performs the simple bind operation defined in the given request
func (l *Conn) SimpleBind(simpleBindRequest *SimpleBindRequest) (*SimpleBindResult, error) {
	if simpleBindRequest.Password == "" && !simpleBindRequest.AllowEmptyPassword {
		return nil, NewError(ErrorEmptyPassword, errors.New("ldap: empty password not allowed by the client"))
	}

	msgCtx, err := l.doRequest(simpleBindRequest)
	if err != nil {
		return nil, err
	}
	defer l.finishMessage(msgCtx)

	packet, err := l.readPacket(msgCtx)
	if err != nil {
		return nil, err
	}

	result := &SimpleBindResult{
		Controls: make([]Control, 0),
	}

	if len(packet.Children) == 3 {
		for _, child := range packet.Children[2].Children {
			decodedChild, decodeErr := DecodeControl(child)
			if decodeErr != nil {
				return nil, fmt.Errorf("failed to decode child control: %s", decodeErr)
			}
			result.Controls = append(result.Controls, decodedChild)
		}
	}

	err = GetLDAPError(packet)
	return result, err
}

// Bind performs a bind with the given username and password.
//
// It does not allow unauthenticated bind (i.e. empty password). Use the UnauthenticatedBind method
// for that.
func (l *Conn) Bind(username, password string) error {
	req := &SimpleBindRequest{
		Username:           username,
		Password:           password,
		AllowEmptyPassword: false,
	}
	_, err := l.SimpleBind(req)
	return err
}

// UnauthenticatedBind performs an unauthenticated bind.
//
// A username may be provided for trace (e.g. logging) purpose only, but it is normally not
// authenticated or otherwise validated by the LDAP server.
//
// See https://tools.ietf.org/html/rfc4513#section-5.1.2 .
// See https://tools.ietf.org/html/rfc4513#section-6.3.1 .
func (l *Conn) UnauthenticatedBind(username string) error {
	req := &SimpleBindRequest{
		Username:           username,
		Password:           "",
		AllowEmptyPassword: true,
	}
	_, err := l.SimpleBind(req)
	return err
}

var externalBindRequest = requestFunc(func(envelope *ber.Packet) error {
	pkt := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	pkt.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	pkt.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))

	saslAuth := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, "", "authentication")
	saslAuth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "EXTERNAL", "SASL Mech"))
	saslAuth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "SASL Cred"))

	pkt.AppendChild(saslAuth)

	envelope.AppendChild(pkt)

	return nil
})

// ExternalBind performs SASL/EXTERNAL authentication.
//
// Use ldap.DialURL("ldapi://") to connect to the Unix socket before ExternalBind.
//
// See https://tools.ietf.org/html/rfc4422#appendix-A
func (l *Conn) ExternalBind() error {
	msgCtx, err := l.doRequest(externalBindRequest)
	if err != nil {
		return err
	}
	defer l.finishMessage(msgCtx)

	packet, err := l.readPacket(msgCtx)
	if err != nil {
		return err
	}

	return GetLDAPError(packet)
}

// GSSAPIClient interface is used as the client-side implementation for the
// GSSAPI SASL mechanism.
// Interface inspired by GSSAPIClient from golang.org/x/crypto/ssh
type GSSAPIClient interface {
	// InitSecContext initiates the establishment of a security context for
	// GSS-API between the client and server.
	// Initially the token parameter should be specified as nil.
	// The routine may return a outputToken which should be transferred to
	// the server, where the server will present it to AcceptSecContext.
	// If no token need be sent, InitSecContext will indicate this by setting
	// needContinue to false. To complete the context
	// establishment, one or more reply tokens may be required from the server;
	// if so, InitSecContext will return a needContinue which is true.
	// In this case, InitSecContext should be called again when the
	// reply token is received from the server, passing the reply token
	// to InitSecContext via the token parameters.
	// See RFC 4752 section 3.1.
	InitSecContext(target string, token []byte) (outputToken []byte, needContinue bool, err error)
	// InitSecContextWithOptions is the same as InitSecContext but allows for additional options to be passed to the context establishment.
	// See RFC 4752 section 3.1.
	InitSecContextWithOptions(target string, token []byte, options []int) (outputToken []byte, needContinue bool, err error)
	// NegotiateSaslAuth performs the last step of the Sasl handshake.
	// It takes a token, which, when unwrapped, describes the servers supported
	// security layers (first octet) and maximum receive buffer (remaining
	// three octets).
	// If the received token is unacceptable an error must be returned to abort
	// the handshake.
	// Outputs a signed token describing the client's selected security layer
	// and receive buffer size and optionally an authorization identity.
	// The returned token will be sent to the server and the handshake considered
	// completed successfully and the server authenticated.
	// See RFC 4752 section 3.1.
	NegotiateSaslAuth(token []byte, authzid string) ([]byte, error)
	// DeleteSecContext destroys any established secure context.
	DeleteSecContext() error
}

// GSSAPIBindRequest represents a GSSAPI SASL mechanism bind request.
// See rfc4752 and rfc4513 section 5.2.1.2.
type GSSAPIBindRequest struct {
	// Service Principal Name user for the service ticket. Eg. "ldap/<host>"
	ServicePrincipalName string
	// (Optional) Authorization entity
	AuthZID string
	// (Optional) Controls to send with the bind request
	Controls []Control
}

// GSSAPIBind performs the GSSAPI SASL bind using the provided GSSAPI client.
func (l *Conn) GSSAPIBind(client GSSAPIClient, servicePrincipal, authzid string) error {
	return l.GSSAPIBindRequest(client, &GSSAPIBindRequest{
		ServicePrincipalName: servicePrincipal,
		AuthZID:              authzid,
	})
}

// GSSAPIBindRequest performs the GSSAPI SASL bind using the provided GSSAPI client.
func (l *Conn) GSSAPIBindRequest(client GSSAPIClient, req *GSSAPIBindRequest) error {
	return l.GSSAPIBindRequestWithAPOptions(client, req, []int{})
}

// GSSAPIBindRequestWithAPOptions performs the GSSAPI SASL bind using the provided GSSAPI client.
func (l *Conn) GSSAPIBindRequestWithAPOptions(client GSSAPIClient, req *GSSAPIBindRequest, APOptions []int) error {
	//nolint:errcheck
	defer client.DeleteSecContext()

	var err error
	var reqToken []byte
	var recvToken []byte
	needInit := true
	for {
		if needInit {
			// Establish secure context between client and server.
			reqToken, needInit, err = client.InitSecContextWithOptions(req.ServicePrincipalName, recvToken, APOptions)
			if err != nil {
				return err
			}
		} else {
			// Secure context is set up, perform the last step of SASL handshake.
			reqToken, err = client.NegotiateSaslAuth(recvToken, req.AuthZID)
			if err != nil {
				return err
			}
		}
		// Send Bind request containing the current token and extract the
		// token sent by server.
		recvToken, err = l.saslBindTokenExchange(req.Controls, reqToken)
		if err != nil {
			return err
		}

		if !needInit && len(recvToken) == 0 {
			break
		}
	}

	return nil
}

func (l *Conn) saslBindTokenExchange(reqControls []Control, reqToken []byte) ([]byte, error) {
	// Construct LDAP Bind request with GSSAPI SASL mechanism.
	envelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	envelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))

	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))

	auth := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, "", "authentication")
	auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "GSSAPI", "SASL Mech"))
	if len(reqToken) > 0 {
		auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(reqToken), "Credentials"))
	}
	request.AppendChild(auth)
	envelope.AppendChild(request)
	if len(reqControls) > 0 {
		envelope.AppendChild(encodeControls(reqControls))
	}

	msgCtx, err := l.sendMessage(envelope)
	if err != nil {
		return nil, err
	}
	defer l.finishMessage(msgCtx)

	packet, err := l.readPacket(msgCtx)
	if err != nil {
		return nil, err
	}
	l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
	if l.Debug {
		if err = addLDAPDescriptions(packet); err != nil {
			return nil, err
		}
		ber.PrintPacket(packet)
	}

	// https://www.rfc-editor.org/rfc/rfc4511#section-4.1.1
	// packet is an envelope
	// child 0 is message id
	// child 1 is protocolOp
	if len(packet.Children) != 2 {
		return nil, fmt.Errorf("bad bind response")
	}

	protocolOp := packet.Children[1]
RESP:
	switch protocolOp.Description {
	case "Bind Response": // Bind Response
		// Bind Reponse is an LDAP Response (https://www.rfc-editor.org/rfc/rfc4511#section-4.1.9)
		// with an additional optional serverSaslCreds string (https://www.rfc-editor.org/rfc/rfc4511#section-4.2.2)
		// child 0 is resultCode
		resultCode := protocolOp.Children[0]
		if resultCode.Tag != ber.TagEnumerated {
			break RESP
		}
		switch resultCode.Value.(int64) {
		case 14: // Sasl bind in progress
			if len(protocolOp.Children) < 3 {
				break RESP
			}
			referral := protocolOp.Children[3]
			switch referral.Description {
			case "Referral":
				if referral.ClassType != ber.ClassContext || referral.Tag != ber.TagObjectDescriptor {
					break RESP
				}
				return ioutil.ReadAll(referral.Data)
			}
			// Optional:
			//if len(protocolOp.Children) == 4 {
			//	serverSaslCreds := protocolOp.Children[4]
			//}
		case 0: // Success - Bind OK.
			// SASL layer in effect (if any) (See https://www.rfc-editor.org/rfc/rfc4513#section-5.2.1.4)
			// NOTE: SASL security layers are not supported currently.
			return nil, nil
		}
	}

	return nil, GetLDAPError(packet)
}
