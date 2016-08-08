package ldap

import (
	"testing"
)

func TestControlManageDsaITEncodeDecode(t *testing.T) {
	c := NewControlManageDsaIT(true)
	packet := c.Encode()
	_ = DecodeControl(packet)

	c = NewControlManageDsaIT(false)
	packet = c.Encode()
	_ = DecodeControl(packet)
}
