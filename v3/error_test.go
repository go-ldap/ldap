package ldap

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
)

// TestWrappedError tests that match the result code when an error is wrapped.
func TestWrappedError(t *testing.T) {
	resultCodes := []uint16{
		LDAPResultProtocolError,
		LDAPResultBusy,
		ErrorNetwork,
	}

	tests := []struct {
		name     string
		err      error
		codes    []uint16
		expected bool
	}{
		// success
		{
			name: "a normal error",
			err: &Error{
				ResultCode: ErrorNetwork,
			},
			codes:    resultCodes,
			expected: true,
		},

		{
			name: "a wrapped error",
			err: fmt.Errorf("wrap: %w", &Error{
				ResultCode: LDAPResultBusy,
			}),
			codes:    resultCodes,
			expected: true,
		},

		{
			name: "multiple wrapped error",
			err: fmt.Errorf("second: %w",
				fmt.Errorf("first: %w",
					&Error{
						ResultCode: LDAPResultProtocolError,
					},
				),
			),
			codes:    resultCodes,
			expected: true,
		},

		// failure
		{
			name: "not match a normal error",
			err: &Error{
				ResultCode: LDAPResultSuccess,
			},
			codes:    resultCodes,
			expected: false,
		},

		{
			name: "not match a wrapped error",
			err: fmt.Errorf("wrap: %w", &Error{
				ResultCode: LDAPResultNoSuchObject,
			}),
			codes:    resultCodes,
			expected: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			actual := IsErrorAnyOf(tt.err, tt.codes...)
			if tt.expected != actual {
				t.Errorf("expected %t, but got %t", tt.expected, actual)
			}
		})
	}
}

// TestConnReadErr tests that an unexpected error reading from underlying
// connection bubbles up to the goroutine which makes a request.
func TestConnReadErr(t *testing.T) {
	conn := &signalErrConn{
		signals: make(chan error),
	}

	ldapConn := NewConn(conn, false)
	ldapConn.Start()

	// Make a dummy search request.
	searchReq := NewSearchRequest("dc=example,dc=com", ScopeWholeSubtree, DerefAlways, 0, 0, false, "(objectClass=*)", nil, nil)

	expectedError := errors.New("this is the error you are looking for")

	// Send the signal after a short amount of time.
	time.AfterFunc(10*time.Millisecond, func() { conn.signals <- expectedError })

	// This should block until the underlying conn gets the error signal
	// which should bubble up through the reader() goroutine, close the
	// connection, and
	_, err := ldapConn.Search(searchReq)
	if err == nil || !strings.Contains(err.Error(), expectedError.Error()) {
		t.Errorf("not the expected error: %s", err)
	}
}

type testCorpusErrorEntry struct {
	packet             *ber.Packet
	expectedError      error
	expectedResultCode uint16
	expectedMessage    string
	shouldError        bool
}

func generateGetLDAPErrorCorpus() map[string]testCorpusErrorEntry {
	corpus := make(map[string]testCorpusErrorEntry)

	diagnosticMessage := "Detailed error message"
	bindResponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Bind Response")
	bindResponse.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(LDAPResultInvalidCredentials), "resultCode"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc=example,dc=org", "matchedDN"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diagnosticMessage, "diagnosticMessage"))
	packet := ber.NewSequence("LDAPMessage")
	packet.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "messageID"))
	packet.AppendChild(bindResponse)
	corpus["detailed errror message"] = testCorpusErrorEntry{
		packet:             packet,
		expectedResultCode: LDAPResultInvalidCredentials,
		expectedMessage:    diagnosticMessage,
		shouldError:        true,
	}

	bindResponse = ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Bind Response")
	bindResponse.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "resultCode"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "diagnosticMessage"))
	packet = ber.NewSequence("LDAPMessage")
	packet.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "messageID"))
	packet.AppendChild(bindResponse)
	corpus["no error"] = testCorpusErrorEntry{
		packet:             packet,
		expectedResultCode: ErrorNetwork,
		expectedMessage:    "",
	}

	// Test that responses with an unexpected ordering or combination of children
	// don't cause a panic.
	bindResponse = ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Bind Response")
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc=example,dc=org", "matchedDN"))
	bindResponse.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(LDAPResultInvalidCredentials), "resultCode"))
	bindResponse.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(LDAPResultInvalidCredentials), "resultCode"))
	packet = ber.NewSequence("LDAPMessage")
	packet.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "messageID"))
	packet.AppendChild(bindResponse)
	corpus["unexpected ordering"] = testCorpusErrorEntry{
		packet:             packet,
		expectedResultCode: ErrorNetwork,
		expectedMessage:    "Invalid packet format",
		shouldError:        true,
	}

	// Test that a nil ber Packet errors correctly and does not cause a panic.
	corpus["nil packet"] = testCorpusErrorEntry{
		packet:             nil,
		expectedResultCode: ErrorUnexpectedResponse,
		expectedMessage:    "Empty packet",
		shouldError:        true,
	}

	// Test that a nil first child errors correctly and does not cause a panic.
	kids := []*ber.Packet{
		{},  // Unused
		nil, // Can't be nil
	}
	packet = &ber.Packet{Children: kids}
	corpus["nil first child"] = testCorpusErrorEntry{
		packet:             packet,
		expectedResultCode: ErrorUnexpectedResponse,
		expectedMessage:    "Empty response in packet",
		shouldError:        true,
	}

	// Test that if the result code is nil, we get an appropriate error instead of a panic.
	// Panic message would be "interface conversion: interface {} is nil, not int64"
	diagnosticMessage = "Invalid result code in packet"
	bindResponse = ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Bind Response")
	bindResponse.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, nil, "resultCode"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "dc=example,dc=org", "matchedDN"))
	bindResponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, diagnosticMessage, "diagnosticMessage"))
	packet = ber.NewSequence("LDAPMessage")
	packet.AppendChild(ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(0), "messageID"))
	packet.AppendChild(bindResponse)
	corpus["nil result code"] = testCorpusErrorEntry{
		packet:             packet,
		expectedResultCode: ErrorNetwork,
		expectedMessage:    diagnosticMessage,
		shouldError:        true,
	}

	return corpus
}

func TestGetLDAPError(t *testing.T) {
	corpus := generateGetLDAPErrorCorpus()

	for name, entry := range corpus {
		t.Run(name, func(t *testing.T) {
			err := GetLDAPError(entry.packet)

			if !entry.shouldError {
				if err != nil {
					t.Errorf("Did not expect an error, but got: %v", err)
				}
				return
			} else if err == nil {
				t.Errorf("Expected an error response")
				return
			}

			ldapError, ok := err.(*Error)
			if !ok {
				t.Fatalf("Expected error of type *Error, got %T", err)
			}

			if ldapError.ResultCode != entry.expectedResultCode {
				t.Errorf("Got incorrect error code in LDAP error; got %v, expected %v", ldapError.ResultCode, entry.expectedResultCode)
			}
			if ldapError.Err.Error() != entry.expectedMessage {
				t.Errorf("Got incorrect error message in LDAP error; got %v, expected %v", ldapError.Err.Error(), entry.expectedMessage)
			}
		})
	}
}

func FuzzGetLDAPError(f *testing.F) {
	corpus := generateGetLDAPErrorCorpus()
	for _, entry := range corpus {
		if entry.packet != nil {
			f.Add(entry.packet.ByteValue)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		packet, err := ber.ReadPacket(bytes.NewReader(data))
		if err != nil {
			return
		}
		_ = GetLDAPError(packet)
	})
}

func TestErrorIs(t *testing.T) {
	err := NewError(ErrorNetwork, io.EOF)
	if !errors.Is(err, io.EOF) {
		t.Errorf("Expected an io.EOF error: %v", err)
	}
}

func TestErrorAs(t *testing.T) {
	var netErr net.InvalidAddrError = "invalid addr"
	err := NewError(ErrorNetwork, netErr)

	var target net.InvalidAddrError
	ok := errors.As(err, &target)
	if !ok {
		t.Error("Expected an InvalidAddrError")
	}
}

// signalErrConn is a helpful type used with TestConnReadErr. It implements the
// net.Conn interface to be used as a connection for the test. Most methods are
// no-ops but the Read() method blocks until it receives a signal which it
// returns as an error.
type signalErrConn struct {
	signals chan error
}

// Read blocks until an error is sent on the internal signals channel. That
// error is returned.
func (c *signalErrConn) Read(b []byte) (n int, err error) {
	return 0, <-c.signals
}

func (c *signalErrConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (c *signalErrConn) Close() error {
	close(c.signals)
	return nil
}

func (c *signalErrConn) LocalAddr() net.Addr {
	return (*net.TCPAddr)(nil)
}

func (c *signalErrConn) RemoteAddr() net.Addr {
	return (*net.TCPAddr)(nil)
}

func (c *signalErrConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *signalErrConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *signalErrConn) SetWriteDeadline(t time.Time) error {
	return nil
}
