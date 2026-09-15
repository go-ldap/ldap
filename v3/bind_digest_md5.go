//go:build !requirefips

package ldap

import (
	"bytes"
	"crypto/fips140"
	"crypto/md5"
	"crypto/rand"
	enchex "encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// DigestMD5BindRequest represents a digest-md5 bind operation
type DigestMD5BindRequest struct {
	Host string
	// Username is the name of the Directory object that the client wishes to bind as
	Username string
	// Password is the credentials to bind with
	Password string
	// Controls are optional controls to send with the bind request
	Controls []Control
}

func (req *DigestMD5BindRequest) appendTo(envelope *ber.Packet) error {
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
	request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))

	auth := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, "", "authentication")
	auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "DIGEST-MD5", "SASL Mech"))
	request.AppendChild(auth)
	envelope.AppendChild(request)
	if len(req.Controls) > 0 {
		envelope.AppendChild(encodeControls(req.Controls))
	}
	return nil
}

// DigestMD5BindResult contains the response from the server
type DigestMD5BindResult struct {
	Controls []Control
}

// MD5Bind performs a digest-md5 bind with the given host, username and password.
func (l *Conn) MD5Bind(host, username, password string) error {
	req := &DigestMD5BindRequest{
		Host:     host,
		Username: username,
		Password: password,
	}
	_, err := l.DigestMD5Bind(req)
	return err
}

// DigestMD5Bind performs the digest-md5 bind operation defined in the given request
func (l *Conn) DigestMD5Bind(digestMD5BindRequest *DigestMD5BindRequest) (*DigestMD5BindResult, error) {
	if fips140.Enabled() {
		return nil, errors.New("ldap: DIGEST-MD5 is not available in FIPS mode; use GSSAPIBind (Kerberos) or SimpleBind over TLS")
	}

	if digestMD5BindRequest.Password == "" {
		return nil, NewError(ErrorEmptyPassword, errors.New("ldap: empty password not allowed by the client"))
	}

	msgCtx, err := l.doRequest(digestMD5BindRequest)
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

	result := &DigestMD5BindResult{
		Controls: make([]Control, 0),
	}
	var params map[string]string
	if len(packet.Children) == 2 {
		if len(packet.Children[1].Children) == 4 {
			child := packet.Children[1].Children[0]
			if child.Tag != ber.TagEnumerated {
				return result, GetLDAPError(packet)
			}
			if child.Value.(int64) != 14 {
				return result, GetLDAPError(packet)
			}
			child = packet.Children[1].Children[3]
			if child.Tag != ber.TagObjectDescriptor {
				return result, GetLDAPError(packet)
			}
			if child.Data == nil {
				return result, GetLDAPError(packet)
			}
			data, _ := ioutil.ReadAll(child.Data)
			params, err = parseParams(string(data))
			if err != nil {
				return result, fmt.Errorf("parsing digest-challenge: %s", err)
			}
		}
	}

	if len(params) > 0 {
		resp, err := computeResponse(
			params,
			"ldap/"+strings.ToLower(digestMD5BindRequest.Host),
			digestMD5BindRequest.Username,
			digestMD5BindRequest.Password,
		)
		if err != nil {
			return nil, fmt.Errorf("compute digest-md5 response: %s", err)
		}
		packet = ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
		packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, l.nextMessageID(), "MessageID"))

		request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
		request.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, "Version"))
		request.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "User Name"))

		auth := ber.Encode(ber.ClassContext, ber.TypeConstructed, 3, "", "authentication")
		auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "DIGEST-MD5", "SASL Mech"))
		auth.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, resp, "Credentials"))
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

		if len(packet.Children) == 2 {
			response := packet.Children[1]
			if response == nil {
				return result, GetLDAPError(packet)
			}
			if response.ClassType == ber.ClassApplication && response.TagType == ber.TypeConstructed && len(response.Children) >= 3 {
				if ber.Type(response.Children[0].Tag) == ber.Type(ber.TagInteger) || ber.Type(response.Children[0].Tag) == ber.Type(ber.TagEnumerated) {
					resultCode := uint16(response.Children[0].Value.(int64))
					if resultCode == 14 {
						msgCtx, err := l.doRequest(digestMD5BindRequest)
						if err != nil {
							return nil, err
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
				}
			}
		}
	}

	err = GetLDAPError(packet)
	return result, err
}

func parseParams(str string) (map[string]string, error) {
	m := make(map[string]string)
	var key, value string
	var state int
	var escaped bool
	for i := 0; i <= len(str); i++ {
		switch state {
		case 0: // reading key
			if i == len(str) {
				return nil, fmt.Errorf("syntax error on %d", i)
			}
			// The digest-challenge is an RFC 2068 #rule (RFC 2831 section 2.1.1),
			// which permits optional linear whitespace around the comma directive
			// separators. Directive names are tokens that never contain
			// whitespace, so skip it here; otherwise a directive following
			// "..., name" is keyed with a leading space and the lookups in
			// computeResponse (realm, nonce, authzid) miss it.
			if str[i] == ' ' || str[i] == '\t' {
				continue
			}
			if str[i] != '=' {
				key += string(str[i])
				continue
			}
			state = 1
		case 1: // reading value
			if i == len(str) {
				m[key] = value
				break
			}
			// Linear whitespace outside a quoted string is not part of the
			// value: an unquoted value is a token and a quoted value's content
			// is read in the quoted state below. Skipping it lets a challenge
			// using the whitespace the #rule allows (e.g. `nonce="n" , qop=auth`)
			// parse the same as the unspaced form.
			if str[i] == ' ' || str[i] == '\t' {
				continue
			}
			switch str[i] {
			case ',':
				m[key] = value
				state = 0
				key = ""
				value = ""
			case '"':
				if value != "" {
					return nil, fmt.Errorf("syntax error on %d", i)
				}
				state = 2
			default:
				value += string(str[i])
			}
		case 2: // inside quotes
			if i == len(str) {
				return nil, fmt.Errorf("syntax error on %d", i)
			}
			switch {
			case escaped:
				// RFC 2831 section 7.1 quoted-pair: a backslash escapes the
				// following character, so the next byte is taken literally
				// (this is how a server sends a literal " or \ in a realm or
				// nonce).
				value += string(str[i])
				escaped = false
			case str[i] == '\\':
				escaped = true
			case str[i] == '"':
				state = 1
			default:
				value += string(str[i])
			}
		}
	}
	return m, nil
}

func computeResponse(params map[string]string, uri, username, password string) (string, error) {
	nc := "00000001"
	qop := "auth"
	rb, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	cnonce := enchex.EncodeToString(rb)
	x := username + ":" + params["realm"] + ":" + password
	y := md5Hash([]byte(x))

	a1 := bytes.NewBuffer(y)
	a1.WriteString(":" + params["nonce"] + ":" + cnonce)
	if len(params["authzid"]) > 0 {
		a1.WriteString(":" + params["authzid"])
	}
	a2 := bytes.NewBuffer([]byte("AUTHENTICATE"))
	a2.WriteString(":" + uri)
	ha1 := enchex.EncodeToString(md5Hash(a1.Bytes()))
	ha2 := enchex.EncodeToString(md5Hash(a2.Bytes()))

	kd := ha1
	kd += ":" + params["nonce"]
	kd += ":" + nc
	kd += ":" + cnonce
	kd += ":" + qop
	kd += ":" + ha2
	resp := enchex.EncodeToString(md5Hash([]byte(kd)))
	return fmt.Sprintf(
		`username="%s",realm="%s",nonce="%s",cnonce="%s",nc=00000001,qop=%s,digest-uri="%s",response=%s`,
		quotedStringEscape(username),
		quotedStringEscape(params["realm"]),
		quotedStringEscape(params["nonce"]),
		cnonce,
		qop,
		quotedStringEscape(uri),
		resp,
	), nil
}

// quotedStringEscape escapes the two characters that may not appear unescaped
// inside a DIGEST-MD5 quoted string per RFC 2831 section 7.1: the backslash
// and the double quote. The backslash is replaced first so the quotes escaped
// afterwards are not doubled.
func quotedStringEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func md5Hash(b []byte) []byte {
	hasher := md5.New()
	hasher.Write(b)
	return hasher.Sum(nil)
}

func randomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
