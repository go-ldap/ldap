// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"fmt"

	"gopkg.in/asn1-ber.v1"
)

const (
	ControlTypePaging               = "1.2.840.113556.1.4.319"
	ControlTypeBeheraPasswordPolicy = "1.3.6.1.4.1.42.2.27.8.5.1"
)

var ControlTypeMap = map[string]string{
	ControlTypePaging:               "Paging",
	ControlTypeBeheraPasswordPolicy: "Password Policy - Behera Draft",
}

type Control interface {
	GetControlType() string
	Encode() *ber.Packet
	String() string
}

type ControlString struct {
	ControlType  string
	Criticality  bool
	ControlValue string
}

func (c *ControlString) GetControlType() string {
	return c.ControlType
}

func (c *ControlString) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.ControlType, "Control Type ("+ControlTypeMap[c.ControlType]+")"))
	if c.Criticality {
		packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.Criticality, "Criticality"))
	}
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(c.ControlValue), "Control Value"))
	return packet
}

func (c *ControlString) String() string {
	return fmt.Sprintf("Control Type: %s (%q)  Criticality: %t  Control Value: %s", ControlTypeMap[c.ControlType], c.ControlType, c.Criticality, c.ControlValue)
}

type ControlPaging struct {
	PagingSize uint32
	Cookie     []byte
}

func (c *ControlPaging) GetControlType() string {
	return ControlTypePaging
}

func (c *ControlPaging) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypePaging, "Control Type ("+ControlTypeMap[ControlTypePaging]+")"))

	p2 := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Paging)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Search Control Value")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, uint64(c.PagingSize), "Paging Size"))
	cookie := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Cookie")
	cookie.Value = c.Cookie
	cookie.Data.Write(c.Cookie)
	seq.AppendChild(cookie)
	p2.AppendChild(seq)

	packet.AppendChild(p2)
	return packet
}

func (c *ControlPaging) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  PagingSize: %d  Cookie: %q",
		ControlTypeMap[ControlTypePaging],
		ControlTypePaging,
		false,
		c.PagingSize,
		c.Cookie)
}

func (c *ControlPaging) SetCookie(cookie []byte) {
	c.Cookie = cookie
}

type ControlBeheraPasswordPolicy struct {
	Expire      int64
	Grace       int64
	Error       int8
	ErrorString string
}

func (c *ControlBeheraPasswordPolicy) GetControlType() string {
	return ControlTypeBeheraPasswordPolicy
}

func (c *ControlBeheraPasswordPolicy) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeBeheraPasswordPolicy, "Control Type ("+ControlTypeMap[ControlTypeBeheraPasswordPolicy]+")"))

	return packet
}

func (c *ControlBeheraPasswordPolicy) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  Expire: %d  Grace: %d  Error: %d, ErrorString: %s",
		ControlTypeMap[ControlTypeBeheraPasswordPolicy],
		ControlTypeBeheraPasswordPolicy,
		false,
		c.Expire,
		c.Grace,
		c.Error,
		c.ErrorString)
}

func FindControl(controls []Control, controlType string) Control {
	for _, c := range controls {
		if c.GetControlType() == controlType {
			return c
		}
	}
	return nil
}

func DecodeControl(packet *ber.Packet) Control {
	ControlType := packet.Children[0].Value.(string)
	Criticality := false

	packet.Children[0].Description = "Control Type (" + ControlTypeMap[ControlType] + ")"
	value := packet.Children[1]
	if len(packet.Children) == 3 {
		value = packet.Children[2]
		packet.Children[1].Description = "Criticality"
		Criticality = packet.Children[1].Value.(bool)
	}

	value.Description = "Control Value"
	switch ControlType {
	case ControlTypePaging:
		value.Description += " (Paging)"
		c := new(ControlPaging)
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
		c.PagingSize = uint32(value.Children[0].Value.(uint64))
		c.Cookie = value.Children[1].Data.Bytes()
		value.Children[1].Value = c.Cookie
		return c
	case ControlTypeBeheraPasswordPolicy:
		value.Description += " (Password Policy - Behera)"
		c := NewControlBeheraPasswordPolicy()
		if value.Value != nil {
			valueChildren := ber.DecodePacket(value.Data.Bytes())
			value.Data.Truncate(0)
			value.Value = nil
			value.AppendChild(valueChildren)
		}

		sequence := value.Children[0]

		for _, child := range sequence.Children {
			if child.Tag == 0 {
				//Warning
				child := child.Children[0]
				if child.Tag == 0 {
					//timeBeforeExpiration
					c.Expire = int64(ber.DecodeInteger(child.Data.Bytes()))
					child.Value = c.Expire
				} else if child.Tag == 1 {
					//graceAuthNsRemaining
					c.Grace = int64(ber.DecodeInteger(child.Data.Bytes()))
					child.Value = c.Grace
				}
			} else if child.Tag == 1 {
				// Error
				c.Error = int8(ber.DecodeInteger(child.Data.Bytes()))
				child.Value = c.Error
				c.ErrorString = BeheraPasswordPolicyErrorMap[c.Error]
			}
		}
		return c
	}
	c := new(ControlString)
	c.ControlType = ControlType
	c.Criticality = Criticality
	c.ControlValue = value.Value.(string)
	return c
}

func NewControlString(controlType string, criticality bool, controlValue string) *ControlString {
	return &ControlString{
		ControlType:  controlType,
		Criticality:  criticality,
		ControlValue: controlValue,
	}
}

func NewControlPaging(pagingSize uint32) *ControlPaging {
	return &ControlPaging{PagingSize: pagingSize}
}

func NewControlBeheraPasswordPolicy() *ControlBeheraPasswordPolicy {
	return &ControlBeheraPasswordPolicy{
		Expire: -1,
		Grace:  -1,
		Error:  -1,
	}
}

func encodeControls(controls []Control) *ber.Packet {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	for _, control := range controls {
		packet.AppendChild(control.Encode())
	}
	return packet
}
