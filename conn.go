// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package provides LDAP client functions.
package ldap

import (
   "github.com/mmitton/asn1-ber"
   "crypto/tls"
   "fmt"
   "net"
   "os"
   "sync"
)

// LDAP Connection
type Conn struct {
	conn net.Conn
   isSSL bool
   Debug bool

   chanResults map[ uint64 ] chan *ber.Packet
   chanProcessMessage chan *messagePacket
   chanMessageID chan uint64

   closeLock sync.Mutex
}

// Dial connects to the given address on the given network using net.Dial
// and then returns a new Conn for the connection.
func Dial(network, addr string) (*Conn, *Error) {
	c, err := net.Dial(network, "", addr)
	if err != nil {
		return nil, NewError( ErrorNetwork, err )
	}
   conn := NewConn(c)
   conn.start()
	return conn, nil
}

// Dial connects to the given address on the given network using net.Dial
// and then sets up SSL connection and returns a new Conn for the connection.
func DialSSL(network, addr string) (*Conn, *Error) {
	c, err := tls.Dial(network, "", addr, nil)
	if err != nil {
		return nil, NewError( ErrorNetwork, err )
	}
   conn := NewConn(c)
   conn.isSSL = true

   conn.start()
	return conn, nil
}

// Dial connects to the given address on the given network using net.Dial
// and then starts a TLS session and returns a new Conn for the connection.
func DialTLS(network, addr string) (*Conn, *Error) {
	c, err := net.Dial(network, "", addr)
	if err != nil {
		return nil, NewError( ErrorNetwork, err )
	}
   conn := NewConn(c)

   err = conn.startTLS()
   if err != nil {
      conn.Close()
      return nil, NewError( ErrorNetwork, err )
   }
   conn.start()
	return conn, nil
}

// NewConn returns a new Conn using conn for network I/O.
func NewConn(conn net.Conn) *Conn {
	return &Conn{
		conn: conn,
      isSSL: false,
      Debug: false,
      chanResults: map[uint64] chan *ber.Packet{},
      chanProcessMessage: make( chan *messagePacket ),
      chanMessageID: make( chan uint64 ),
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

   l.sendProcessMessage( &messagePacket{ Op: MessageQuit } )

   if l.conn != nil {
      err := l.conn.Close()
      if err != nil {
         return NewError( ErrorNetwork, err )
      }
      l.conn = nil
   }
	return nil
}

// Returns the next available messageID
func (l *Conn) nextMessageID() (messageID uint64) {
   defer func() { if r := recover(); r != nil { messageID = 0 } }()
   messageID = <-l.chanMessageID
   return
}

// StartTLS sends the command to start a TLS session and then creates a new TLS Client
func (l *Conn) startTLS() *Error {
   messageID := l.nextMessageID()

   if l.isSSL {
      return NewError( ErrorNetwork, os.NewError( "Already encrypted" ) )
   }

   packet := ber.Encode( ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request" )
   packet.AppendChild( ber.NewInteger( ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, messageID, "MessageID" ) )
   startTLS := ber.Encode( ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "Start TLS" )
   startTLS.AppendChild( ber.NewString( ber.ClassContext, ber.TypePrimative, 0, "1.3.6.1.4.1.1466.20037", "TLS Extended Command" ) )
   packet.AppendChild( startTLS )
   if l.Debug {
      ber.PrintPacket( packet )
   }

   _, err := l.conn.Write( packet.Bytes() )
   if err != nil {
      return NewError( ErrorNetwork, err )
   }

   packet, err = ber.ReadPacket( l.conn )
   if err != nil {
      return NewError( ErrorNetwork, err )
   }

   if l.Debug {
      if err := addLDAPDescriptions( packet ); err != nil {
         return NewError( ErrorDebugging, err )
      }
      ber.PrintPacket( packet )
   }

   if packet.Children[ 1 ].Children[ 0 ].Value.(uint64) == 0 {
      conn := tls.Client( l.conn, nil )
      l.isSSL = true
      l.conn = conn
   }

   return nil
}

const (
   MessageQuit = 0
   MessageRequest = 1
   MessageResponse = 2
   MessageFinish = 3
)

type messagePacket struct {
   Op int
   MessageID uint64
   Packet *ber.Packet
   Channel chan *ber.Packet
}

func (l *Conn) sendMessage( p *ber.Packet ) (out chan *ber.Packet, err *Error) {
   message_id := p.Children[ 0 ].Value.(uint64)
   out = make(chan *ber.Packet)

   if l.chanProcessMessage == nil {
      err = NewError( ErrorNetwork, os.NewError( "Connection closed" ) )
      return
   }
   message_packet := &messagePacket{ Op: MessageRequest, MessageID: message_id, Packet: p, Channel: out }
   l.sendProcessMessage( message_packet )
   return
}

func (l *Conn) processMessages() {
   defer l.closeAllChannels()

   var message_id uint64 = 1
   var message_packet *messagePacket
   for {
      select {
         case l.chanMessageID <- message_id:
            if l.conn == nil {
               return
            }
            message_id++
         case message_packet = <-l.chanProcessMessage:
            if l.conn == nil {
               return
            }
            switch message_packet.Op {
               case MessageQuit:
                  // Close all channels and quit
                  if l.Debug {
                     fmt.Printf( "Shutting down\n" )
                  }
                  return
               case MessageRequest:
                  // Add to message list and write to network
                  if l.Debug {
                     fmt.Printf( "Sending message %d\n", message_packet.MessageID )
                  }
                  l.chanResults[ message_packet.MessageID ] = message_packet.Channel
                  buf := message_packet.Packet.Bytes()
                  for len( buf ) > 0 {
                     n, err := l.conn.Write( buf )
                     if err != nil {
                        if l.Debug {
                           fmt.Printf( "Error Sending Message: %s\n", err.String() )
                        }
                        return
                     }
                     if n == len( buf ) {
                        break
                     }
                     buf = buf[n:]
                  }
               case MessageResponse:
                  // Pass back to waiting goroutine
                  if l.Debug {
                     fmt.Printf( "Receiving message %d\n", message_packet.MessageID )
                  }
                  chanResult := l.chanResults[ message_packet.MessageID ]
                  if chanResult == nil {
                     fmt.Printf( "Unexpected Message Result: %d\n", message_id )
                     ber.PrintPacket( message_packet.Packet )
                  } else {
                     go func() { chanResult <- message_packet.Packet }()
                     // chanResult <- message_packet.Packet
                  }
               case MessageFinish:
                  // Remove from message list
                  if l.Debug {
                     fmt.Printf( "Finished message %d\n", message_packet.MessageID )
                  }
                  l.chanResults[ message_packet.MessageID ] = nil, false
            }
      }
   }
}

func (l *Conn) closeAllChannels() {
fmt.Printf( "closeAllChannels\n" )
   for MessageID, Channel := range l.chanResults {
      if l.Debug {
         fmt.Printf( "Closing channel for MessageID %d\n", MessageID );
      }
      close( Channel )
      l.chanResults[ MessageID ] = nil, false
   }
   close( l.chanMessageID )
   l.chanMessageID = nil

   close( l.chanProcessMessage )
   l.chanProcessMessage = nil
}

func (l *Conn) finishMessage( MessageID uint64 ) {
   message_packet := &messagePacket{ Op: MessageFinish, MessageID: MessageID }
   l.sendProcessMessage( message_packet )
}

func (l *Conn) reader() {
   defer l.Close()
   for {
      p, err := ber.ReadPacket( l.conn )
      if err != nil {
         if l.Debug {
            fmt.Printf( "ldap.reader: %s\n", err.String() )
         }
         return
      }

      addLDAPDescriptions( p )

      message_id := p.Children[ 0 ].Value.(uint64)
      message_packet := &messagePacket{ Op: MessageResponse, MessageID: message_id, Packet: p }
      if l.chanProcessMessage != nil {
         l.chanProcessMessage <- message_packet
      } else {
         fmt.Printf( "ldap.reader: Cannot return message\n" )
         return
      }
   }
}

func (l *Conn) sendProcessMessage( message *messagePacket ) {
   if l.chanProcessMessage != nil {
      go func() { l.chanProcessMessage <- message }()
   }
}
