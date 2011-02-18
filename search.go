// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// File contains Search functionality
package ldap

import (
   "github.com/mmitton/asn1-ber"
   "fmt"
   "os"
)

const (
   ScopeBaseObject   = 0
   ScopeSingleLevel  = 1
   ScopeWholeSubtree = 2
)

var ScopeMap = map[ int ] string {
   ScopeBaseObject   : "Base Object",
   ScopeSingleLevel  : "Single Level",
   ScopeWholeSubtree : "Whole Subtree",
}

const (
   NeverDerefAliases   = 0
   DerefInSearching    = 1
   DerefFindingBaseObj = 2
   DerefAlways         = 3
)

var DerefMap = map[ int ] string {
   NeverDerefAliases   : "NeverDerefAliases",
   DerefInSearching    : "DerefInSearching",
   DerefFindingBaseObj : "DerefFindingBaseObj",
   DerefAlways         : "DerefAlways",
}

type Entry struct {
   DN string
   Attributes []*EntryAttribute
}

type EntryAttribute struct {
   Name string
   Values []string
}

type SearchResult struct {
   Entries []*Entry
   Referrals []string
   Controls []Control
}

func (e *Entry) GetAttributeValues( Attribute string ) []string {
   for _, attr := range e.Attributes {
      if attr.Name == Attribute {
         return attr.Values
      }
   }

   return []string{ }
}

func (e *Entry) GetAttributeValue( Attribute string ) string {
   values := e.GetAttributeValues( Attribute )
   if len( values ) == 0 {
      return ""
   }
   return values[ 0 ]
}

type SearchRequest struct {
   BaseDN string
   Scope int
   DerefAliases int
   SizeLimit int
   TimeLimit int
   TypesOnly bool
   Filter string
   Attributes []string
   Controls []Control
}

func NewSearchRequest(
      BaseDN string,
      Scope, DerefAliases, SizeLimit, TimeLimit int,
      TypesOnly bool,
      Filter string,
      Attributes []string,
      Controls []Control,
      ) (*SearchRequest) {
   return &SearchRequest{
      BaseDN: BaseDN,
      Scope: Scope,
      DerefAliases: DerefAliases,
      SizeLimit: SizeLimit,
      TimeLimit: TimeLimit,
      TypesOnly: TypesOnly,
      Filter: Filter,
      Attributes: Attributes,
      Controls: Controls,
   }
}

func (l *Conn) SearchWithPaging( SearchRequest *SearchRequest, PagingSize uint32 ) (*SearchResult, *Error) {
   if SearchRequest.Controls == nil {
      SearchRequest.Controls = make( []Control, 0 )
   }

   PagingControl := NewControlPaging( PagingSize )
   SearchRequest.Controls = append( SearchRequest.Controls, PagingControl )
   SearchResult := new( SearchResult )
   for {
      result, err := l.Search( SearchRequest )
      if err != nil {
         return SearchResult, err
      }
      if result == nil {
         return SearchResult, NewError( ErrorNetwork, os.NewError( "Packet not received" ) )
      }

      for _, entry := range result.Entries {
         SearchResult.Entries = append( SearchResult.Entries, entry )
      }
      for _, referral := range result.Referrals {
         SearchResult.Referrals = append( SearchResult.Referrals, referral )
      }
      for _, control := range result.Controls {
         SearchResult.Controls = append( SearchResult.Controls, control )
      }

      paging_result := FindControl( result.Controls, ControlTypePaging )
      if paging_result == nil {
         PagingControl = nil
         break
      }

      cookie := paging_result.(*ControlPaging).Cookie
      if len( cookie ) == 0 {
         PagingControl = nil
         break
      }
      PagingControl.SetCookie( cookie )
   }

   if PagingControl != nil {
      PagingControl.PagingSize = 0
      l.Search( SearchRequest )
   }

   return SearchResult, nil
}

func (l *Conn) Search( SearchRequest *SearchRequest ) (*SearchResult, *Error) {
   messageID := l.nextMessageID()

   packet := ber.Encode( ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request" )
   packet.AppendChild( ber.NewInteger( ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, messageID, "MessageID" ) )
   searchRequest := ber.Encode( ber.ClassApplication, ber.TypeConstructed, ApplicationSearchRequest, nil, "Search Request" )
   searchRequest.AppendChild( ber.NewString( ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, SearchRequest.BaseDN, "Base DN" ) )
   searchRequest.AppendChild( ber.NewInteger( ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(SearchRequest.Scope), "Scope" ) )
   searchRequest.AppendChild( ber.NewInteger( ber.ClassUniversal, ber.TypePrimative, ber.TagEnumerated, uint64(SearchRequest.DerefAliases), "Deref Aliases" ) )
   searchRequest.AppendChild( ber.NewInteger( ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(SearchRequest.SizeLimit), "Size Limit" ) )
   searchRequest.AppendChild( ber.NewInteger( ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, uint64(SearchRequest.TimeLimit), "Time Limit" ) )
   searchRequest.AppendChild( ber.NewBoolean( ber.ClassUniversal, ber.TypePrimative, ber.TagBoolean, SearchRequest.TypesOnly, "Types Only" ) )
   filterPacket, err := CompileFilter( SearchRequest.Filter )
   if err != nil {
      return nil, err
   }
   searchRequest.AppendChild( filterPacket )
   attributesPacket := ber.Encode( ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes" )
   for _, attribute := range SearchRequest.Attributes {
      attributesPacket.AppendChild( ber.NewString( ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, attribute, "Attribute" ) )
   }
   searchRequest.AppendChild( attributesPacket )
   packet.AppendChild( searchRequest )
   if SearchRequest.Controls != nil {
      packet.AppendChild( encodeControls( SearchRequest.Controls ) )
   }

   if l.Debug {
      ber.PrintPacket( packet )
   }

   channel, err := l.sendMessage( packet )
   if err != nil {
      return nil, err
   }
   if channel == nil {
      return nil, NewError( ErrorNetwork, os.NewError( "Could not send message" ) )
   }
   defer l.finishMessage( messageID )

   result := new( SearchResult )

   foundSearchResultDone := false
   for !foundSearchResultDone {
      if l.Debug {
         fmt.Printf( "%d: waiting for response\n", messageID )
      }
      packet = <-channel
      if l.Debug {
         fmt.Printf( "%d: got response\n", messageID, packet )
      }
      if packet == nil {
         return nil, NewError( ErrorNetwork, os.NewError( "Could not retrieve message" ) )
      }

      if l.Debug {
         if err := addLDAPDescriptions( packet ); err != nil {
            return nil, NewError( ErrorDebugging, err )
         }
         ber.PrintPacket( packet )
      }

      switch packet.Children[ 1 ].Tag {
         case 4:
            entry := new( Entry )
            entry.DN = packet.Children[ 1 ].Children[ 0 ].Value.(string)
            for _, child := range packet.Children[ 1 ].Children[ 1 ].Children {
               attr := new( EntryAttribute )
               attr.Name = child.Children[ 0 ].Value.(string)
               for _, value := range child.Children[ 1 ].Children {
                  attr.Values = append( attr.Values, value.Value.(string) )
               }
               entry.Attributes = append( entry.Attributes, attr )
            }
            result.Entries = append( result.Entries, entry )
         case 5:
            if len( packet.Children ) == 3 {
               for _, child := range packet.Children[ 2 ].Children {
                  result.Controls = append( result.Controls, DecodeControl( child ) )
               }
            }
            foundSearchResultDone = true
         case 19:
            result.Referrals = append( result.Referrals, packet.Children[ 1 ].Children[ 0 ].Value.(string) )
      }
   }

   return result, nil
}
