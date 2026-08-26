//go:build !requirefips

package ldap

import (
	"bytes"
	"crypto/fips140"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode/utf16"

	"github.com/Azure/go-ntlmssp"
	ber "github.com/go-asn1-ber/asn1-ber"
	"golang.org/x/crypto/md4" //nolint:staticcheck
)

// NTLMBindRequest represents an NTLMSSP bind operation
type NTLMBindRequest struct {
	// Domain is the AD Domain to authenticate too. If not specified, it will be grabbed from the NTLMSSP Challenge
	Domain string
	// Username is the name of the Directory object that the client wishes to bind as
	Username string
	// Password is the credentials to bind with
	Password string
	// AllowEmptyPassword sets whether the client allows binding with an empty password
	// (normally used for unauthenticated bind).
	AllowEmptyPassword bool
	// Hash is the hex NTLM hash to bind with. Password or hash must be provided
	Hash string
	// Controls are optional controls to send with the bind request
	Controls []Control
	// Negotiator allows to specify a custom NTLM negotiator.
	Negotiator NTLMNegotiator
}

// NTLMNegotiator is an abstraction of an NTLM implementation that produces and
// processes NTLM binary tokens.
type NTLMNegotiator interface {
	Negotiate(domain string, workstation string) ([]byte, error)
	ChallengeResponse(challenge []byte, username string, hash string) ([]byte, error)
}

func (req *NTLMBindRequest) appendTo(envelope *ber.Packet) (err error) {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))

	var negMessage []byte

	// generate an NTLMSSP Negotiation message for the  specified domain (it can be blank)
	switch {
	case req.Negotiator == nil:
		negMessage, err = ntlmssp.NewNegotiateMessage(req.Domain, "")
		if err != nil {
			return fmt.Errorf("create NTLM negotiate message: %s", err)
		}
	default:
		negMessage, err = req.Negotiator.Negotiate(req.Domain, "")
		if err != nil {
			return fmt.Errorf("create NTLM negotiate message with custom negotiator: %s", err)
		}
	}

	// append the generated NTLMSSP message as a TagEnumerated BER value
	auth := ber.Encode(ber.ClassContext, ber.TypePrimitive, ber.TagEnumerated, negMessage, "authentication")
	request.AppendChild(auth)
	envelope.AppendChild(request)
	if len(req.Controls) > 0 {
		envelope.AppendChild(encodeControls(req.Controls))
	}
	return nil
}

// NTLMBindResult contains the response from the server
type NTLMBindResult struct {
	Controls []Control
}

// NTLMBind performs an NTLMSSP Bind with the given domain, username and password
func (l *Conn) NTLMBind(domain, username, password string) error {
	req := &NTLMBindRequest{
		Domain:   domain,
		Username: username,
		Password: password,
	}
	_, err := l.NTLMChallengeBind(req)
	return err
}

// NTLMUnauthenticatedBind performs an bind with an empty password.
//
// A username is required. The anonymous bind is not (yet) supported by the go-ntlmssp library (https://github.com/Azure/go-ntlmssp/blob/819c794454d067543bc61d29f61fef4b3c3df62c/authenticate_message.go#L87)
//
// See https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b38c36ed-2804-4868-a9ff-8dd3182128e4 part 3.2.5.1.2
func (l *Conn) NTLMUnauthenticatedBind(domain, username string) error {
	req := &NTLMBindRequest{
		Domain:             domain,
		Username:           username,
		Password:           "",
		AllowEmptyPassword: true,
	}
	_, err := l.NTLMChallengeBind(req)
	return err
}

// NTLMBindWithHash performs an NTLM Bind with an NTLM hash instead of plaintext password (pass-the-hash)
func (l *Conn) NTLMBindWithHash(domain, username, hash string) error {
	req := &NTLMBindRequest{
		Domain:   domain,
		Username: username,
		Hash:     hash,
	}
	_, err := l.NTLMChallengeBind(req)
	return err
}

// NTLMChallengeBind performs the NTLMSSP bind operation defined in the given request
func (l *Conn) NTLMChallengeBind(ntlmBindRequest *NTLMBindRequest) (*NTLMBindResult, error) {
	if fips140.Enabled() {
		return nil, errors.New("ldap: NTLM bind is not available in FIPS mode; use GSSAPIBind (Kerberos)")
	}

	if !ntlmBindRequest.AllowEmptyPassword && ntlmBindRequest.Password == "" && ntlmBindRequest.Hash == "" {
		return nil, NewError(ErrorEmptyPassword, errors.New("ldap: empty password not allowed by the client"))
	}

	msgCtx, err := l.doRequest(ntlmBindRequest)
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
	result := &NTLMBindResult{
		Controls: make([]Control, 0),
	}
	var ntlmsspChallenge []byte

	// now find the NTLM Response Message
	if len(packet.Children) == 2 {
		if len(packet.Children[1].Children) == 3 {
			child := packet.Children[1].Children[1]
			ntlmsspChallenge = child.ByteValue
			// Check to make sure we got the right message. It will always start with NTLMSSP
			if len(ntlmsspChallenge) < 7 || !bytes.Equal(ntlmsspChallenge[:7], []byte("NTLMSSP")) {
				return result, GetLDAPError(packet)
			}
			l.Debug.Printf("%d: found ntlmssp challenge", msgCtx.id)
		}
	}
	if ntlmsspChallenge != nil {
		var err error
		var responseMessage []byte

		switch {
		case ntlmBindRequest.Hash == "" && ntlmBindRequest.Password == "" && !ntlmBindRequest.AllowEmptyPassword:
			err = fmt.Errorf("need a password or hash to generate reply")
		case ntlmBindRequest.Negotiator == nil && ntlmBindRequest.Hash != "":
			responseMessage, err = ntlmssp.ProcessChallengeWithHash(ntlmsspChallenge, ntlmBindRequest.Username, ntlmBindRequest.Hash)
		case ntlmBindRequest.Negotiator == nil && (ntlmBindRequest.Password != "" || ntlmBindRequest.AllowEmptyPassword):
			// generate a response message to the challenge with the given Username/Password if password is provided
			_, _, domainNeeded := ntlmssp.GetDomain(ntlmBindRequest.Username)
			responseMessage, err = ntlmssp.ProcessChallenge(ntlmsspChallenge, ntlmBindRequest.Username, ntlmBindRequest.Password, domainNeeded)
		default:
			hash := ntlmBindRequest.Hash
			if len(hash) == 0 {
				hash = ntHash(ntlmBindRequest.Password)
			}

			responseMessage, err = ntlmBindRequest.Negotiator.ChallengeResponse(ntlmsspChallenge, ntlmBindRequest.Username, hash)
		}

		if err != nil {
			return result, fmt.Errorf("process NTLM challenge: %s", err)
		}

		packet = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))

		request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
		request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
		request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))

		// append the challenge response message as a TagEmbeddedPDV BER value
		auth := ber.Encode(ber.ClassContext, ber.TypePrimitive, ber.TagEmbeddedPDV, responseMessage, "authentication")

		request.AppendChild(auth)
		packet.AppendChild(request)
		msgCtx, err = l.sendMessage(packet)
		if err != nil {
			return nil, fmt.Errorf("send message: %s", err)
		}
		defer l.finishMessage(msgCtx)
		packetResponse, ok := <-msgCtx.responses
		if !ok {
			return nil, NewError(ErrorNetwork, errors.New("ldap: response channel closed"))
		}
		packet, err = packetResponse.ReadPacket()
		l.Debug.Printf("%d: got response %p", msgCtx.id, packet)
		if err != nil {
			return nil, fmt.Errorf("read packet: %s", err)
		}

	}

	err = GetLDAPError(packet)
	return result, err
}

func ntHash(pass string) string {
	runes := utf16.Encode([]rune(pass))

	b := bytes.Buffer{}
	_ = binary.Write(&b, binary.LittleEndian, &runes)

	hash := md4.New()
	_, _ = hash.Write(b.Bytes())

	return hex.EncodeToString(hash.Sum(nil))
}
