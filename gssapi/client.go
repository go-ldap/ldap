package gssapi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/types"

	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/spnego"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/messages"

	"github.com/jcmturner/gokrb5/v8/credentials"
)

// Client implements ldap.GSSAPIClient interface.
type Client struct {
	*client.Client

	ekey   types.EncryptionKey
	Subkey types.EncryptionKey

	APOptions []int
}

// NewClientWithKeytab creates a new client from a keytab credential.
// Set the realm to empty string to use the default realm from config.
func NewClientWithKeytab(username, realm, keytabPath, krb5confPath string, settings ...func(*client.Settings)) (*Client, error) {
	krb5conf, err := config.Load(krb5confPath)
	if err != nil {
		return nil, err
	}

	keytab, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, err
	}

	client := client.NewWithKeytab(username, realm, keytab, krb5conf, settings...)

	return &Client{
		Client: client,
	}, nil
}

// NewClientWithPassword creates a new client from a password credential.
// Set the realm to empty string to use the default realm from config.
func NewClientWithPassword(username, realm, password string, krb5confPath string, settings ...func(*client.Settings)) (*Client, error) {
	krb5conf, err := config.Load(krb5confPath)
	if err != nil {
		return nil, err
	}

	client := client.NewWithPassword(username, realm, password, krb5conf, settings...)

	return &Client{
		Client: client,
	}, nil
}

// NewClientFromCCache creates a new client from a populated client cache.
func NewClientFromCCache(ccachePath, krb5confPath string, settings ...func(*client.Settings)) (*Client, error) {
	krb5conf, err := config.Load(krb5confPath)
	if err != nil {
		return nil, err
	}

	ccache, err := credentials.LoadCCache(ccachePath)
	if err != nil {
		return nil, err
	}

	client, err := client.NewFromCCache(ccache, krb5conf, settings...)
	if err != nil {
		return nil, err
	}

	return &Client{
		Client: client,
	}, nil
}

// Close deletes any established secure context and closes the client.
func (client *Client) Close() error {
	client.Client.Destroy()
	return nil
}

// DeleteSecContext destroys any established secure context.
func (client *Client) DeleteSecContext() error {
	client.ekey = types.EncryptionKey{}
	client.Subkey = types.EncryptionKey{}
	return nil
}

// InitSecContext initiates the establishment of a security context for
// GSS-API between the client and server.
// See RFC 4752 section 3.1.
func (client *Client) InitSecContext(target string, input []byte) ([]byte, bool, error) {
	gssapiFlags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf, gssapi.ContextFlagMutual}

	switch input {
	case nil:
		tkt, ekey, err := client.Client.GetServiceTicket(target)
		if err != nil {
			return nil, false, err
		}
		client.ekey = ekey

		token, err := spnego.NewKRB5TokenAPREQ(client.Client, tkt, ekey, gssapiFlags, client.APOptions)
		if err != nil {
			return nil, false, err
		}

		output, err := token.Marshal()
		if err != nil {
			return nil, false, err
		}

		return output, true, nil

	default:
		var token spnego.KRB5Token

		err := token.Unmarshal(input)
		if err != nil {
			return nil, false, err
		}

		var completed bool

		if token.IsAPRep() {
			completed = true

			encpart, err := crypto.DecryptEncPart(token.APRep.EncPart, client.ekey, keyusage.AP_REP_ENCPART)
			if err != nil {
				return nil, false, err
			}

			part := &messages.EncAPRepPart{}

			if err = part.Unmarshal(encpart); err != nil {
				return nil, false, err
			}
			client.Subkey = part.Subkey
		}

		if token.IsKRBError() {
			return nil, !false, token.KRBError
		}

		return make([]byte, 0), !completed, nil
	}
}

// NegotiateSaslAuth performs the last step of the SASL handshake.
// See RFC 4752 section 3.1.
func (client *Client) NegotiateSaslAuth(input []byte, authzid string) ([]byte, error) {
	token := &gssapi.WrapToken{}
	err := unmarshalWrapToken(token, input, true)
	if err != nil {
		return nil, err
	}

	if (token.Flags & 0b1) == 0 {
		return nil, fmt.Errorf("got a Wrapped token that's not from the server")
	}

	key := client.ekey
	if (token.Flags & 0b100) != 0 {
		key = client.Subkey
	}

	_, err = token.Verify(key, keyusage.GSSAPI_ACCEPTOR_SEAL)
	if err != nil {
		return nil, err
	}

	pl := token.Payload
	if len(pl) != 4 {
		return nil, fmt.Errorf("server send bad final token for SASL GSSAPI Handshake")
	}

	// We never want a security layer
	b := [4]byte{0, 0, 0, 0}
	payload := append(b[:], []byte(authzid)...)

	encType, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}

	token = &gssapi.WrapToken{
		Flags:     0b100,
		EC:        uint16(encType.GetHMACBitLength() / 8),
		RRC:       0,
		SndSeqNum: 1,
		Payload:   payload,
	}

	if err := token.SetCheckSum(key, keyusage.GSSAPI_INITIATOR_SEAL); err != nil {
		return nil, err
	}

	output, err := token.Marshal()
	if err != nil {
		return nil, err
	}

	return output, nil
}

func unmarshalWrapToken(wt *gssapi.WrapToken, data []byte, expectFromAcceptor bool) error {
	// Check if we can read a whole header
	if len(data) < 16 {
		return errors.New("bytes shorter than header length")
	}

	// Is the Token ID correct?
	expectedWrapTokenId := [2]byte{0x05, 0x04}
	if !bytes.Equal(expectedWrapTokenId[:], data[0:2]) {
		return fmt.Errorf("wrong Token ID. Expected %s, was %s", hex.EncodeToString(expectedWrapTokenId[:]), hex.EncodeToString(data[0:2]))
	}

	// Check the acceptor flag
	flags := data[2]
	isFromAcceptor := flags&0x01 == 1
	if isFromAcceptor && !expectFromAcceptor {
		return errors.New("unexpected acceptor flag is set: not expecting a token from the acceptor")
	}
	if !isFromAcceptor && expectFromAcceptor {
		return errors.New("expected acceptor flag is not set: expecting a token from the acceptor, not the initiator")
	}

	// Check the filler byte
	if data[3] != gssapi.FillerByte {
		return fmt.Errorf("unexpected filler byte: expecting 0xFF, was %s ", hex.EncodeToString(data[3:4]))
	}
	checksumL := binary.BigEndian.Uint16(data[4:6])

	// Sanity check on the checksum length
	if int(checksumL) > len(data)-gssapi.HdrLen {
		return fmt.Errorf("inconsistent checksum length: %d bytes to parse, checksum length is %d", len(data), checksumL)
	}

	payloadStart := 16 + checksumL

	wt.Flags = flags
	wt.EC = checksumL
	wt.RRC = binary.BigEndian.Uint16(data[6:8])
	wt.SndSeqNum = binary.BigEndian.Uint64(data[8:16])
	wt.CheckSum = data[16:payloadStart]
	wt.Payload = data[payloadStart:]

	return nil
}
