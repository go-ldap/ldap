package ldap

import (
	"fmt"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/google/uuid"
)

const (
	// ControlTypeSyncRequest - https://www.ietf.org/rfc/rfc4533.txt
	ControlTypeSyncRequest = "1.3.6.1.4.1.4203.1.9.1.1"
	// ControlTypeSyncState - https://www.ietf.org/rfc/rfc4533.txt
	ControlTypeSyncState = "1.3.6.1.4.1.4203.1.9.1.2"
	// ControlTypeSyncDone - https://www.ietf.org/rfc/rfc4533.txt
	ControlTypeSyncDone = "1.3.6.1.4.1.4203.1.9.1.3"
	// ControlTypeSyncInfo - https://www.ietf.org/rfc/rfc4533.txt
	ControlTypeSyncInfo = "1.3.6.1.4.1.4203.1.9.1.4"
)

func DecodeSyncReplControl(packet *ber.Packet) (Control, error) {
	var (
		controlType string
		value       *ber.Packet
		err         error
	)
	switch len(packet.Children) {
	case 0:
		return nil, nil
	case 1:
		return nil, nil
	case 2:
		controlType = packet.Children[0].Data.String()
		value, err = ber.DecodePacketErr(packet.Children[1].Data.Bytes())
		if err != nil {
			return nil, fmt.Errorf("failed to decode data bytes: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported handling children: %d", len(packet.Children))
	}

	switch controlType {
	case ControlTypeSyncState:
		value.Description += " (Sync State)"
		return NewControlSyncState(value)
	case ControlTypeSyncDone:
		value.Description += " (Sync Done)"
		return NewControlSyncDone(value)
	case ControlTypeSyncInfo:
		value.Description += " (Sync Info)"
		return NewControlSyncInfo(value)
	default:
		return nil, fmt.Errorf("unsupported control type: %s", controlType)
	}
}

// Mode for ControlTypeSyncRequest
type ControlSyncRequestMode int64

const (
	SyncRequestModeRefreshOnly       ControlSyncRequestMode = 1
	SyncRequestModeRefreshAndPersist ControlSyncRequestMode = 3
)

// ControlSyncRequest implements the Sync Request Control described in https://www.ietf.org/rfc/rfc4533.txt
type ControlSyncRequest struct {
	Criticality bool
	Mode        ControlSyncRequestMode
	Cookie      []byte
	ReloadHint  bool
}

func NewControlSyncRequest(
	mode ControlSyncRequestMode, cookie []byte, reloadHint bool,
) *ControlSyncRequest {
	return &ControlSyncRequest{
		Criticality: true,
		Mode:        mode,
		Cookie:      cookie,
		ReloadHint:  reloadHint,
	}
}

// GetControlType returns the OID
func (c *ControlSyncRequest) GetControlType() string {
	return ControlTypeSyncRequest
}

// Encode encodes the control
func (c *ControlSyncRequest) Encode() *ber.Packet {
	_mode := int64(c.Mode)
	mode := ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, _mode, "Mode")
	cookie := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Cookie")
	cookie.Value = c.Cookie
	cookie.Data.Write(c.Cookie)
	reloadHint := ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.ReloadHint, "Reload Hint")

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Control")
	packet.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ControlTypeSyncRequest, "Control Type ("+ControlTypeMap[ControlTypeSyncRequest]+")"))
	packet.AppendChild(ber.NewBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, c.Criticality, "Criticality"))

	val := ber.Encode(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, nil, "Control Value (Sync Request)")
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Sync Request Value")
	seq.AppendChild(mode)
	seq.AppendChild(cookie)
	seq.AppendChild(reloadHint)
	val.AppendChild(seq)

	packet.AppendChild(val)
	return packet
}

// String returns a human-readable description
func (c *ControlSyncRequest) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t Mode: %d Cookie: %s ReloadHint: %t",
		ControlTypeMap[ControlTypeSyncRequest],
		ControlTypeSyncRequest,
		c.Criticality,
		c.Mode,
		string(c.Cookie),
		c.ReloadHint,
	)
}

// State for ControlSyncState
type ControlSyncStateState int64

const (
	SyncStatePresent ControlSyncStateState = 0
	SyncStateAdd     ControlSyncStateState = 1
	SyncStateModify  ControlSyncStateState = 2
	SyncStateDelete  ControlSyncStateState = 3
)

// ControlSyncState implements the Sync State Control described in https://www.ietf.org/rfc/rfc4533.txt
type ControlSyncState struct {
	Criticality bool
	State       ControlSyncStateState
	EntryUUID   uuid.UUID
	Cookie      []byte
}

func NewControlSyncState(pkt *ber.Packet) (*ControlSyncState, error) {
	var (
		state     ControlSyncStateState
		entryUUID uuid.UUID
		cookie    []byte
		err       error
	)
	switch len(pkt.Children) {
	case 0, 1:
		return nil, fmt.Errorf("at least two children are required: %d", len(pkt.Children))
	case 2:
		state = ControlSyncStateState(pkt.Children[0].Value.(int64))
		entryUUID, err = uuid.FromBytes(pkt.Children[1].ByteValue)
		if err != nil {
			return nil, fmt.Errorf("failed to decode uuid: %w", err)
		}
	case 3:
		state = ControlSyncStateState(pkt.Children[0].Value.(int64))
		entryUUID, err = uuid.FromBytes(pkt.Children[1].ByteValue)
		if err != nil {
			return nil, fmt.Errorf("failed to decode uuid: %w", err)
		}
		cookie = pkt.Children[2].ByteValue
	}
	return &ControlSyncState{
		Criticality: false,
		State:       state,
		EntryUUID:   entryUUID,
		Cookie:      cookie,
	}, nil
}

// GetControlType returns the OID
func (c *ControlSyncState) GetControlType() string {
	return ControlTypeSyncState
}

// Encode encodes the control
func (c *ControlSyncState) Encode() *ber.Packet {
	return nil
}

// String returns a human-readable description
func (c *ControlSyncState) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t State: %d EntryUUID: %s Cookie: %s",
		ControlTypeMap[ControlTypeSyncState],
		ControlTypeSyncState,
		c.Criticality,
		c.State,
		c.EntryUUID.String(),
		string(c.Cookie),
	)
}

// ControlSyncDone implements the Sync Done Control described in https://www.ietf.org/rfc/rfc4533.txt
type ControlSyncDone struct {
	Criticality    bool
	Cookie         []byte
	RefreshDeletes bool
}

func NewControlSyncDone(pkt *ber.Packet) (*ControlSyncDone, error) {
	var (
		cookie         []byte
		refreshDeletes bool
	)
	switch len(pkt.Children) {
	case 0:
		// have nothing to do
	case 1:
		cookie = pkt.Children[0].ByteValue
	case 2:
		cookie = pkt.Children[0].ByteValue
		refreshDeletes = pkt.Children[1].Value.(bool)
	}
	return &ControlSyncDone{
		Criticality:    false,
		Cookie:         cookie,
		RefreshDeletes: refreshDeletes,
	}, nil
}

// GetControlType returns the OID
func (c *ControlSyncDone) GetControlType() string {
	return ControlTypeSyncDone
}

// Encode encodes the control
func (c *ControlSyncDone) Encode() *ber.Packet {
	return nil
}

// String returns a human-readable description
func (c *ControlSyncDone) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t Cookie: %s RefreshDeletes: %t",
		ControlTypeMap[ControlTypeSyncDone],
		ControlTypeSyncDone,
		c.Criticality,
		string(c.Cookie),
		c.RefreshDeletes,
	)
}

// Tag For ControlSyncInfo
type ControlSyncInfoValue uint64

const (
	SyncInfoNewcookie      ControlSyncInfoValue = 0
	SyncInfoRefreshDelete  ControlSyncInfoValue = 1
	SyncInfoRefreshPresent ControlSyncInfoValue = 2
	SyncInfoSyncIdSet      ControlSyncInfoValue = 3
)

// ControlSyncInfoNewCookie implements a part of syncInfoValue described in https://www.ietf.org/rfc/rfc4533.txt
type ControlSyncInfoNewCookie struct {
	Cookie []byte
}

// String returns a human-readable description
func (c *ControlSyncInfoNewCookie) String() string {
	return fmt.Sprintf(
		"NewCookie[Cookie: %s]",
		string(c.Cookie),
	)
}

// ControlSyncInfoRefreshDelete implements a part of syncInfoValue described in https://www.ietf.org/rfc/rfc4533.txt
type ControlSyncInfoRefreshDelete struct {
	Cookie      []byte
	RefreshDone bool
}

// String returns a human-readable description
func (c *ControlSyncInfoRefreshDelete) String() string {
	return fmt.Sprintf(
		"RefreshDelete[Cookie: %s RefreshDone: %t]",
		string(c.Cookie),
		c.RefreshDone,
	)
}

// ControlSyncInfoRefreshPresent implements a part of syncInfoValue described in https://www.ietf.org/rfc/rfc4533.txt
type ControlSyncInfoRefreshPresent struct {
	Cookie      []byte
	RefreshDone bool
}

// String returns a human-readable description
func (c *ControlSyncInfoRefreshPresent) String() string {
	return fmt.Sprintf(
		"RefreshPresent[Cookie: %s RefreshDone: %t]",
		string(c.Cookie),
		c.RefreshDone,
	)
}

// ControlSyncInfoSyncIdSet implements a part of syncInfoValue described in https://www.ietf.org/rfc/rfc4533.txt
type ControlSyncInfoSyncIdSet struct {
	Cookie         []byte
	RefreshDeletes bool
	SyncUUIDs      []uuid.UUID
}

// String returns a human-readable description
func (c *ControlSyncInfoSyncIdSet) String() string {
	return fmt.Sprintf(
		"SyncIdSet[Cookie: %s RefreshDeletes: %t SyncUUIDs: %v]",
		string(c.Cookie),
		c.RefreshDeletes,
		c.SyncUUIDs,
	)
}

// ControlSyncInfo implements the Sync Info Control described in https://www.ietf.org/rfc/rfc4533.txt
type ControlSyncInfo struct {
	Criticality    bool
	Value          ControlSyncInfoValue
	NewCookie      *ControlSyncInfoNewCookie
	RefreshDelete  *ControlSyncInfoRefreshDelete
	RefreshPresent *ControlSyncInfoRefreshPresent
	SyncIdSet      *ControlSyncInfoSyncIdSet
}

func NewControlSyncInfo(pkt *ber.Packet) (*ControlSyncInfo, error) {
	var (
		cookie         []byte
		refreshDone    = true
		refreshDeletes bool
		syncUUIDs      []uuid.UUID
	)
	c := &ControlSyncInfo{Criticality: false}
	switch ControlSyncInfoValue(pkt.Identifier.Tag) {
	case SyncInfoNewcookie:
		c.Value = SyncInfoNewcookie
		c.NewCookie = &ControlSyncInfoNewCookie{
			Cookie: pkt.ByteValue,
		}
	case SyncInfoRefreshDelete:
		c.Value = SyncInfoRefreshDelete
		switch len(pkt.Children) {
		case 0:
			// have nothing to do
		case 1:
			cookie = pkt.Children[0].ByteValue
		case 2:
			cookie = pkt.Children[0].ByteValue
			refreshDone = pkt.Children[1].Value.(bool)
		}
		c.RefreshDelete = &ControlSyncInfoRefreshDelete{
			Cookie:      cookie,
			RefreshDone: refreshDone,
		}
	case SyncInfoRefreshPresent:
		c.Value = SyncInfoRefreshPresent
		switch len(pkt.Children) {
		case 0:
			// have nothing to do
		case 1:
			cookie = pkt.Children[0].ByteValue
		case 2:
			cookie = pkt.Children[0].ByteValue
			refreshDone = pkt.Children[1].Value.(bool)
		}
		c.RefreshPresent = &ControlSyncInfoRefreshPresent{
			Cookie:      cookie,
			RefreshDone: refreshDone,
		}
	case SyncInfoSyncIdSet:
		c.Value = SyncInfoSyncIdSet
		switch len(pkt.Children) {
		case 0:
			// have nothing to do
		case 1:
			cookie = pkt.Children[0].ByteValue
		case 2:
			cookie = pkt.Children[0].ByteValue
			refreshDeletes = pkt.Children[1].Value.(bool)
		case 3:
			cookie = pkt.Children[0].ByteValue
			refreshDeletes = pkt.Children[1].Value.(bool)
			syncUUIDs = make([]uuid.UUID, 0, len(pkt.Children[2].Children))
			for _, child := range pkt.Children[2].Children {
				u, err := uuid.FromBytes(child.ByteValue)
				if err != nil {
					return nil, fmt.Errorf("failed to decode uuid: %w", err)
				}
				syncUUIDs = append(syncUUIDs, u)
			}
		}
		c.SyncIdSet = &ControlSyncInfoSyncIdSet{
			Cookie:         cookie,
			RefreshDeletes: refreshDeletes,
			SyncUUIDs:      syncUUIDs,
		}
	default:
		return nil, fmt.Errorf("unknown sync info value: %d", pkt.Identifier.Tag)
	}
	return c, nil
}

// GetControlType returns the OID
func (c *ControlSyncInfo) GetControlType() string {
	return ControlTypeSyncInfo
}

// Encode encodes the control
func (c *ControlSyncInfo) Encode() *ber.Packet {
	return nil
}

// String returns a human-readable description
func (c *ControlSyncInfo) String() string {
	return fmt.Sprintf(
		"Control Type: %s (%q)  Criticality: %t Value: %d %s %s %s %s",
		ControlTypeMap[ControlTypeSyncInfo],
		ControlTypeSyncInfo,
		c.Criticality,
		c.Value,
		c.NewCookie,
		c.RefreshDelete,
		c.RefreshPresent,
		c.SyncIdSet,
	)
}
