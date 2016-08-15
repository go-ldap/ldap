// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"fmt"

	"gopkg.in/asn1-ber.v1"
)

// ControlTypePaging - https://www.ietf.org/rfc/rfc2696.txt
const ControlTypePaging = "1.2.840.113556.1.4.319"

// ControlPaging implements the paging control described in https://www.ietf.org/rfc/rfc2696.txt
type ControlPaging struct {
	// PagingSize indicates the page size
	PagingSize uint32
	// Cookie is an opaque value returned by the server to track a paging cursor
	Cookie []byte
}

// GetControlType returns the OID
func (c *ControlPaging) GetControlType() string {
	return ControlTypePaging
}

func init() {
	RegisterControl(ControlTypePaging, "Paging", &ControlPaging{})
}

// Encode returns the ber packet representation
func (c *ControlPaging) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypePaging, "Control Type ("+ControlDescription(ControlTypePaging)+")"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Paging)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Search Control Value")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(c.PagingSize), "Paging Size"))
	cookie := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Cookie")
	cookie.Value = c.Cookie
	cookie.Data.Write(c.Cookie)
	seq.AppendChild(cookie)
	p2.AppendChild(seq)

	packet.AppendChild(p2)
	return packet
}

// Describe adds descritptions to the control value
func (c *ControlPaging) Describe(value *ber.Packet) {
	value.Description += " (Paging)"
	if value.Value != nil {
		valueChildren := ber.DecodePacket(value.Data.Bytes())
		value.Data.Truncate(0)
		value.Value = nil
		valueChildren.Children[1].Value = valueChildren.Children[1].Data.Bytes()
		value.AppendChild(valueChildren)
	}
	value.Children[0].Description = "Real Search Control Value"
	value.Children[0].Children[0].Description = "Paging Size"
	value.Children[0].Children[1].Description = "Cookie"
}

// String returns a human-readable description
func (c *ControlPaging) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  PagingSize: %d  Cookie: %q",
		ControlDescription(ControlTypePaging),
		ControlTypePaging,
		false,
		c.PagingSize,
		c.Cookie)
}

// SetCookie stores the given cookie in the paging control
func (c *ControlPaging) SetCookie(cookie []byte) {
	c.Cookie = cookie
}

// Decode decodes a ControlPaging control value
func (c *ControlPaging) Decode(criticality bool, value *ber.Packet) (Control, error) {
	value.Description += " (Paging)"
	if value.Value != nil {
		valueChildren := ber.DecodePacket(value.Data.Bytes())
		value.Data.Truncate(0)
		value.Value = nil
		value.AppendChild(valueChildren)
	}
	value = value.Children[0]
	value.Description = "Search Control Value"
	value.Children[0].Description = "Paging Size"
	value.Children[1].Description = "Cookie"
	c.PagingSize = uint32(value.Children[0].Value.(int64))
	c.Cookie = value.Children[1].Data.Bytes()
	value.Children[1].Value = c.Cookie
	return c, nil
}

// NewControlPaging returns a paging control
func NewControlPaging(pagingSize uint32) *ControlPaging {
	return &ControlPaging{PagingSize: pagingSize}
}
