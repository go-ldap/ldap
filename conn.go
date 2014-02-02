// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package provides LDAP client functions.
package ldap

import (
	"crypto/tls"
	"errors"
	"github.com/tmfkams/asn1-ber"
	"log"
	"net"
	"sync"
)

const (
	MessageQuit     = 0
	MessageRequest  = 1
	MessageResponse = 2
	MessageFinish   = 3
)

type messagePacket struct {
	Op        int
	MessageID uint64
	Packet    *ber.Packet
	Channel   chan *ber.Packet
}

// LDAP Connection
type Conn struct {
	conn          net.Conn
	isSSL         bool
	isClosed      bool
	Debug         debugging
	chanConfirm   chan int
	chanResults   map[uint64]chan *ber.Packet
	chanMessage   chan *messagePacket
	chanMessageID chan uint64
	closeLock     sync.Mutex
}

// Dial connects to the given address on the given network using net.Dial
// and then returns a new Conn for the connection.
func Dial(network, addr string) (*Conn, *Error) {
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewConn(c)
	conn.start()
	return conn, nil
}

// Dial connects to the given address on the given network using net.Dial
// and then sets up SSL connection and returns a new Conn for the connection.
func DialSSL(network, addr string, config *tls.Config) (*Conn, *Error) {
	c, err := tls.Dial(network, addr, config)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewConn(c)
	conn.isSSL = true
	conn.start()
	return conn, nil
}

// Dial connects to the given address on the given network using net.Dial
// and then starts a TLS session and returns a new Conn for the connection.
func DialTLS(network, addr string, config *tls.Config) (*Conn, *Error) {
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := NewConn(c)
	if err := conn.startTLS(config); err != nil {
		conn.Close()
		return nil, NewError(ErrorNetwork, err.Err)
	}
	conn.start()
	return conn, nil
}

// NewConn returns a new Conn using conn for network I/O.
func NewConn(conn net.Conn) *Conn {
	return &Conn{
		conn:          conn,
		isSSL:         false,
		isClosed:      false,
		Debug:         false,
		chanConfirm:   make(chan int),
		chanMessageID: make(chan uint64),
		chanMessage:   make(chan *messagePacket, 10),
		chanResults:   map[uint64]chan *ber.Packet{},
	}
}

func (l *Conn) start() {
	go l.reader()
	go l.processMessages()
}

// Close closes the connection.
func (l *Conn) Close() *Error {
	l.closeLock.Lock()
	defer l.closeLock.Unlock()

	// close only once
	if l.isClosed {
		return nil
	}

	l.Debug.Printf("Sending quit message\n")
	l.chanMessage <- &messagePacket{Op: MessageQuit}
	<-l.chanConfirm
	l.chanConfirm = nil

	l.Debug.Printf("Closing network connection\n")
	if err := l.conn.Close(); err != nil {
		return NewError(ErrorNetwork, err)
	}

	l.isClosed = true
	return nil
}

// Returns the next available messageID
func (l *Conn) nextMessageID() uint64 {
	// l.chanMessageID will be set to nil by processMessage()
	if l.chanMessageID != nil {
		if messageID, ok := <-l.chanMessageID; ok {
			return messageID
		}
	}
	return 0
}

// StartTLS sends the command to start a TLS session and then creates a new TLS Client
func (l *Conn) startTLS(config *tls.Config) *Error {
	messageID := l.nextMessageID()

	if l.isSSL {
		return NewError(ErrorNetwork, errors.New("Already encrypted"))
	}

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, messageID, "MessageID"))
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "Start TLS")
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, 0, "1.3.6.1.4.1.1466.20037", "TLS Extended Command"))
	packet.AppendChild(request)
	l.Debug.PrintPacket(packet)

	_, err := l.conn.Write(packet.Bytes())
	if err != nil {
		return NewError(ErrorNetwork, err)
	}

	packet, err = ber.ReadPacket(l.conn)
	if err != nil {
		return NewError(ErrorNetwork, err)
	}

	if l.Debug {
		if err := addLDAPDescriptions(packet); err != nil {
			return NewError(ErrorDebugging, err.Err)
		}
		ber.PrintPacket(packet)
	}

	if packet.Children[1].Children[0].Value.(uint64) == 0 {
		conn := tls.Client(l.conn, config)
		l.isSSL = true
		l.conn = conn
	}

	return nil
}

func (l *Conn) sendMessage(packet *ber.Packet) (chan *ber.Packet, *Error) {
	out := make(chan *ber.Packet)
	// l.chanMessage will be set to nil by processMessage()
	if l.chanMessage != nil {
		l.chanMessage <- &messagePacket{
			Op:        MessageRequest,
			MessageID: packet.Children[0].Value.(uint64),
			Packet:    packet,
			Channel:   out,
		}
	} else {
		return nil, NewError(ErrorNetwork, errors.New("Connection closed"))
	}
	return out, nil
}

func (l *Conn) processMessages() {
	defer func() {
		for messageID, channel := range l.chanResults {
			if channel != nil {
				l.Debug.Printf("Closing channel for MessageID %d\n", messageID)
				close(channel)
				l.chanResults[messageID] = nil
			}
		}
		// l.chanMessage should be closed by sender but there is more than one
		close(l.chanMessage)
		l.chanMessage = nil
		close(l.chanMessageID)
		// l.chanMessageID should be set to nil by nextMessageID() but it is not a go routine
		l.chanMessageID = nil
		close(l.chanConfirm)
	}()

	var messageID uint64 = 1
	for {
		select {
		case l.chanMessageID <- messageID:
			messageID++
		case messagePacket := <-l.chanMessage:
			switch messagePacket.Op {
			case MessageQuit:
				l.Debug.Printf("Shutting down\n")
				l.chanConfirm <- 1
				return
			case MessageRequest:
				// Add to message list and write to network
				l.Debug.Printf("Sending message %d\n", messagePacket.MessageID)
				l.chanResults[messagePacket.MessageID] = messagePacket.Channel
				buf := messagePacket.Packet.Bytes()
				// TODO: understand
				for len(buf) > 0 {
					n, err := l.conn.Write(buf)
					if err != nil {
						l.Debug.Printf("Error Sending Message: %s\n", err.Error())
						l.Close()
						break
					}
					// nothing else to send
					if n == len(buf) {
						break
					}
					// the remaining buf content
					buf = buf[n:]
				}
			case MessageResponse:
				l.Debug.Printf("Receiving message %d\n", messagePacket.MessageID)
				if chanResult, ok := l.chanResults[messagePacket.MessageID]; ok {
					chanResult <- messagePacket.Packet
				} else {
					log.Printf("Unexpected Message Result: %d\n", messagePacket.MessageID)
					ber.PrintPacket(messagePacket.Packet)
				}
			case MessageFinish:
				// Remove from message list
				l.Debug.Printf("Finished message %d\n", messagePacket.MessageID)
				l.chanResults[messagePacket.MessageID] = nil
			}
		}
	}
}

func (l *Conn) finishMessage(MessageID uint64) {
	// l.chanMessage will be set to nil by processMessage()
	if l.chanMessage != nil {
		l.chanMessage <- &messagePacket{Op: MessageFinish, MessageID: MessageID}
	}
}

func (l *Conn) reader() {
	defer func() {
		l.Close()
		l.conn = nil
	}()

	for {
		packet, err := ber.ReadPacket(l.conn)
		if err != nil {
			l.Debug.Printf("ldap.reader: %s\n", err.Error())
			return
		}

		addLDAPDescriptions(packet)

		if l.chanMessage != nil {
			l.chanMessage <- &messagePacket{
				Op:        MessageResponse,
				MessageID: packet.Children[0].Value.(uint64),
				Packet:    packet,
			}
		} else {
			log.Printf("ldap.reader: Cannot return message, channel is already closed\n")
			return
		}
	}
}
