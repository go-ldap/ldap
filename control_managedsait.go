// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"errors"
	"fmt"

	"gopkg.in/asn1-ber.v1"
)

// ControlTypeManageDsaIT - https://tools.ietf.org/html/rfc3296
const ControlTypeManageDsaIT = "2.16.840.1.113730.3.4.2"

// ControlManageDsaIT implements the control described in https://tools.ietf.org/html/rfc3296
// The boolean value indicates if this control is required
type ControlManageDsaIT bool

func init() {
	RegisterControl(ControlTypeManageDsaIT, "Manage DSA IT", ControlManageDsaIT(false))
}

// GetControlType returns the OID
func (c ControlManageDsaIT) GetControlType() string {
	return ControlTypeManageDsaIT
}

// Describe adds descriptions to the value
func (c ControlManageDsaIT) Describe(value *ber.Packet) {
	// no control value, just return
	return
}

// Encode returns the ber packet representation
func (c ControlManageDsaIT) Encode() *ber.Packet {
	//FIXME
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeManageDsaIT, "Control Type ("+ControlDescription(ControlTypeManageDsaIT)+")"))
	if c {
		packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, bool(c), "Criticality"))
	}
	return packet
}

// String returns a human-readable description
func (c ControlManageDsaIT) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t",
		ControlDescription(ControlTypeManageDsaIT),
		ControlTypeManageDsaIT,
		c)
}

// NewControlManageDsaIT returns a ControlManageDsaIT control
func NewControlManageDsaIT(Criticality bool) ControlManageDsaIT {
	return ControlManageDsaIT(Criticality)
}

// Decode decodes a ControlManageDsaIT control value
func (c ControlManageDsaIT) Decode(criticality bool, value *ber.Packet) (Control, error) {
	c = ControlManageDsaIT(criticality)
	if value != nil {
		return nil, errors.New("unexpected value != nil")
	}
	return c, nil
}
