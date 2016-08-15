// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ldap

import (
	"errors"
	"fmt"
	"reflect"
	"sync"

	"gopkg.in/asn1-ber.v1"
)

// controlTypeMap maps controls to text descriptions
var controlTypeMap = make(map[string]controlType)
var controlTypeMapLock = sync.Mutex{}

type controlType struct {
	Description string
	Control     Control
}

// RegisterControl adds a Control to the map of known Controls.
func RegisterControl(oid, description string, ctrl Control) {
	if ctrl == nil {
		return
	}
	controlTypeMapLock.Lock()
	defer controlTypeMapLock.Unlock()
	controlTypeMap[oid] = controlType{
		Control:     ctrl,
		Description: description,
	}
}

// GetControl returns an empty new initialized Control for the
// given ControlType (OID). Returns nil if the Control has not
// been registered with RegisterControl() before.
func GetControl(oid string) Control {
	controlTypeMapLock.Lock()
	ctrl, ok := controlTypeMap[oid]
	controlTypeMapLock.Unlock()
	if !ok {
		return nil
	}
	// Indirect returns the value that v points to. [...] If v is
	// not a pointer, Indirect returns v.
	refVal := reflect.ValueOf(ctrl.Control)
	indVal := reflect.Indirect(refVal)
	if refVal == indVal {
		// we got something like "type ControlManageDsaIT bool" as Control.
		// reflect.New returns pointer type -> use indirect
		return reflect.Indirect(reflect.New(refVal.Type())).Interface().(Control)
	}
	// got pointer to something as Control
	return reflect.New(indVal.Type()).Interface().(Control)
}

// ControlDescription returns the description for the Control as it was
// passed to RegisterControl().
func ControlDescription(oid string) string {
	controlTypeMapLock.Lock()
	defer controlTypeMapLock.Unlock()
	ctrl, ok := controlTypeMap[oid]
	if !ok {
		return ""
	}
	return ctrl.Description
}

// Control defines an interface controls provide to encode,
// decode and describe themselves
type Control interface {
	// GetControlType returns the OID
	GetControlType() string
	// Encode returns the ber packet representation
	Encode() *ber.Packet
	// String returns a human-readable description
	String() string
	// Decode decodes the Control
	Decode(bool, *ber.Packet) (Control, error)
	// Describe adds descritptions to the control value
	Describe(*ber.Packet)
}

// ControlString implements the Control interface for simple controls
type ControlString struct {
	ControlType  string
	Criticality  bool
	ControlValue string
}

// GetControlType returns the OID
func (c *ControlString) GetControlType() string {
	return c.ControlType
}

// Encode returns the ber packet representation
func (c *ControlString) Encode() *ber.Packet {
	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, c.ControlType, "Control Type ("+ControlDescription(c.ControlType)+")"))
	if c.Criticality {
		packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.Criticality, "Criticality"))
	}
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, string(c.ControlValue), "Control Value"))
	return packet
}

// String returns a human-readable description
func (c *ControlString) String() string {
	return fmt.Sprintf("Control Type: %s (%q)  Criticality: %t  Control Value: %s", ControlDescription(c.ControlType), c.ControlType, c.Criticality, c.ControlValue)
}

// FindControl returns the first control of the given type in the list, or nil
func FindControl(controls []Control, controlType string) Control {
	for _, c := range controls {
		if c.GetControlType() == controlType {
			return c
		}
	}
	return nil
}

// DecodeControl returns a control read from the given packet, or nil if no recognized control can be made
func DecodeControl(packet *ber.Packet) (Control, error) {
	var (
		ControlType = ""
		Criticality = false
		value       *ber.Packet
	)

	switch len(packet.Children) {
	case 0:
		// at least one child is required for control type
		return nil, errors.New("at least one child is required for control type")

	case 1:
		// just type, no criticality or value
		packet.Children[0].Description = "Control Type (" + ControlDescription(ControlType) + ")"
		ControlType = packet.Children[0].Value.(string)

	case 2:
		packet.Children[0].Description = "Control Type (" + ControlDescription(ControlType) + ")"
		ControlType = packet.Children[0].Value.(string)

		// Children[1] could be criticality or value (both are optional)
		// duck-type on whether this is a boolean
		if _, ok := packet.Children[1].Value.(bool); ok {
			packet.Children[1].Description = "Criticality"
			Criticality = packet.Children[1].Value.(bool)
		} else {
			packet.Children[1].Description = "Control Value"
			value = packet.Children[1]
		}

	case 3:
		packet.Children[0].Description = "Control Type (" + ControlDescription(ControlType) + ")"
		ControlType = packet.Children[0].Value.(string)

		packet.Children[1].Description = "Criticality"
		Criticality = packet.Children[1].Value.(bool)

		packet.Children[2].Description = "Control Value"
		value = packet.Children[2]

	default:
		// more than 3 children is invalid
		return nil, errors.New("more than 3 children is invalid")
	}

	ctrl := GetControl(ControlType)
	var err error
	if ctrl != nil {
		if ctrl, err = ctrl.Decode(Criticality, value); err != nil {
			return nil, err
		}
		return ctrl, nil
	}
	cs := new(ControlString)
	cs.ControlType = ControlType
	if ctrl, err = cs.Decode(Criticality, value); err != nil { // should not happen
		return nil, err
	}
	return ctrl, nil
}

// Describe adds description to the control value. For the ControlString
// it's a no-op.
func (c *ControlString) Describe(_ *ber.Packet) {
	return
}

// Decode decodes the control value.
func (c *ControlString) Decode(Criticality bool, value *ber.Packet) (Control, error) {
	c.Criticality = Criticality
	if value != nil {
		c.ControlValue = value.Value.(string)
	}
	return c, nil
}

// NewControlString returns a generic control
func NewControlString(controlType string, criticality bool, controlValue string) *ControlString {
	return &ControlString{
		ControlType:  controlType,
		Criticality:  criticality,
		ControlValue: controlValue,
	}
}

func encodeControls(controls []Control) *ber.Packet {
	packet := ber.Encode(ber.ClassContext, ber.TypeConstructed, 0, nil, "Controls")
	for _, control := range controls {
		packet.AppendChild(control.Encode())
	}
	return packet
}
