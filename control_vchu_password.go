// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"fmt"
	"strconv"

	"gopkg.in/asn1-ber.v1"
)

// ControlTypeVChuPasswordMustChange - https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
const ControlTypeVChuPasswordMustChange = "2.16.840.1.113730.3.4.4"

// ControlTypeVChuPasswordWarning - https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
const ControlTypeVChuPasswordWarning = "2.16.840.1.113730.3.4.5"

func init() {
	RegisterControl(ControlTypeVChuPasswordMustChange, "VChu Password Must Change", &ControlVChuPasswordMustChange{})
	RegisterControl(ControlTypeVChuPasswordWarning, "VChu Password Warning", &ControlVChuPasswordWarning{})
}

// ControlVChuPasswordMustChange implements the control described in https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
type ControlVChuPasswordMustChange struct {
	// MustChange indicates if the password is required to be changed
	MustChange bool
}

// GetControlType returns the OID
func (c *ControlVChuPasswordMustChange) GetControlType() string {
	return ControlTypeVChuPasswordMustChange
}

// Describe adds descritptions to the control value
func (c *ControlVChuPasswordMustChange) Describe(value *ber.Packet) {
	// FIXME
	return
}

// Encode returns the ber packet representation
func (c *ControlVChuPasswordMustChange) Encode() *ber.Packet {
	return nil
}

// String returns a human-readable description
func (c *ControlVChuPasswordMustChange) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  MustChange: %v",
		ControlDescription(ControlTypeVChuPasswordMustChange),
		ControlTypeVChuPasswordMustChange,
		false,
		c.MustChange)
}

// ControlVChuPasswordWarning implements the control described in https://tools.ietf.org/html/draft-vchu-ldap-pwd-policy-00
type ControlVChuPasswordWarning struct {
	// Expire indicates the time in seconds until the password expires
	Expire int64
}

// GetControlType returns the OID
func (c *ControlVChuPasswordWarning) GetControlType() string {
	return ControlTypeVChuPasswordWarning
}

// Describe adds descritptions to the control value
func (c *ControlVChuPasswordWarning) Describe(value *ber.Packet) {
	// FIXME
	return
}

// Encode returns the ber packet representation
func (c *ControlVChuPasswordWarning) Encode() *ber.Packet {
	return nil
}

// String returns a human-readable description
func (c *ControlVChuPasswordWarning) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t  Expire: %b",
		ControlDescription(ControlTypeVChuPasswordWarning),
		ControlTypeVChuPasswordWarning,
		false,
		c.Expire)
}

// Decode decodes a ControlVChuPasswordMustChange control value
func (c *ControlVChuPasswordMustChange) Decode(criticality bool, value *ber.Packet) (Control, error) {
	return c, nil // FIXME
}

// Decode decodes a ControlVChuPasswordWarning control value
func (c *ControlVChuPasswordWarning) Decode(criticality bool, value *ber.Packet) (Control, error) {
	c.Expire = -1
	expireStr := ber.DecodeString(value.Data.Bytes())

	expire, err := strconv.ParseInt(expireStr, 10, 64)
	if err != nil {
		return nil, err
	}
	c.Expire = expire
	value.Value = c.Expire
	return c, nil
}
