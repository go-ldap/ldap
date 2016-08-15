// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"fmt"

	"gopkg.in/asn1-ber.v1"
)

// ControlTypeBeheraPasswordPolicy - https://tools.ietf.org/html/draft-behera-ldap-password-policy-10
const ControlTypeBeheraPasswordPolicy = "1.3.6.1.4.1.42.2.27.8.5.1"

// ControlBeheraPasswordPolicy implements the control described in https://tools.ietf.org/html/draft-behera-ldap-password-policy-10
type ControlBeheraPasswordPolicy struct {
	// Expire contains the number of seconds before a password will expire
	Expire int64
	// Grace indicates the remaining number of times a user will be allowed to authenticate with an expired password
	Grace int64
	// Error indicates the error code
	Error int8
	// ErrorString is a human readable error
	ErrorString string
}

func init() {
	RegisterControl(ControlTypeBeheraPasswordPolicy, "Password Policy - Behera Draft", &ControlBeheraPasswordPolicy{})
}

// GetControlType returns the OID
func (c *ControlBeheraPasswordPolicy) GetControlType() string {
	return ControlTypeBeheraPasswordPolicy
}

// Encode returns the ber packet representation
func (c *ControlBeheraPasswordPolicy) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeBeheraPasswordPolicy, "Control Type ("+ControlDescription(ControlTypeBeheraPasswordPolicy)+")"))

	return packet
}

// String returns a human-readable description
func (c *ControlBeheraPasswordPolicy) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  Expire: %d  Grace: %d  Error: %d, ErrorString: %s",
		ControlDescription(ControlTypeBeheraPasswordPolicy),
		ControlTypeBeheraPasswordPolicy,
		false,
		c.Expire,
		c.Grace,
		c.Error,
		c.ErrorString)
}

// Describe adds descritptions to the control value
func (c *ControlBeheraPasswordPolicy) Describe(value *ber.Packet) {
	value.Description += " (Password Policy - Behera Draft)"
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
			packet := ber.DecodePacket(child.Data.Bytes())
			val, ok := packet.Value.(int64)
			if ok {
				if child.Tag == 0 {
					//timeBeforeExpiration
					value.Description += " (TimeBeforeExpiration)"
					child.Value = val
				} else if child.Tag == 1 {
					//graceAuthNsRemaining
					value.Description += " (GraceAuthNsRemaining)"
					child.Value = val
				}
			}
		} else if child.Tag == 1 {
			// Error
			packet := ber.DecodePacket(child.Data.Bytes())
			val, ok := packet.Value.(int8)
			if !ok {
				val = -1
			}
			child.Description = "Error"
			child.Value = val
		}
	}
}

// Decode decodes a ControlBeheraPasswordPolicy control value
func (c *ControlBeheraPasswordPolicy) Decode(criticality bool, value *ber.Packet) (Control, error) {
	value.Description += " (Password Policy - Behera)"
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
			packet := ber.DecodePacket(child.Data.Bytes())
			val, ok := packet.Value.(int64)
			if ok {
				if child.Tag == 0 {
					//timeBeforeExpiration
					c.Expire = val
					child.Value = c.Expire
				} else if child.Tag == 1 {
					//graceAuthNsRemaining
					c.Grace = val
					child.Value = c.Grace
				}
			}
		} else if child.Tag == 1 {
			// Error
			packet := ber.DecodePacket(child.Data.Bytes())
			val, ok := packet.Value.(int8)
			if !ok {
				// what to do?
				val = -1
			}
			c.Error = val
			child.Value = c.Error
			c.ErrorString = BeheraPasswordPolicyErrorMap[c.Error]
		}
	}
	return c, nil
}

// NewControlBeheraPasswordPolicy returns a ControlBeheraPasswordPolicy
func NewControlBeheraPasswordPolicy() *ControlBeheraPasswordPolicy {
	return &ControlBeheraPasswordPolicy{
		Expire: -1,
		Grace:  -1,
		Error:  -1,
	}
}
