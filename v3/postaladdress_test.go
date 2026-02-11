package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPostalAddressRoundTrip(t *testing.T) {
	testStrings := []struct {
		Escaped  string
		Expected string
	}{
		{
			Escaped:  "1234 Main St.$Anytown, CA 12345$USA",
			Expected: "1234 Main St.\nAnytown, CA 12345\nUSA",
		},
		{
			Escaped:  `\241,000,000 Sweepstakes$PO Box 1000000$Anytown, CA 12345$USA`,
			Expected: "$1,000,000 Sweepstakes\nPO Box 1000000\nAnytown, CA 12345\nUSA",
		},
	}
	for _, str := range testStrings {
		t.Run(str.Escaped, func(t *testing.T) {
			escaped, err := ParsePostalAddress(str.Escaped)
			assert.NoError(t, err)
			assert.Equal(t, str.Expected, escaped.String())

			addr := NewPostalAddress([]string{str.Expected})
			assert.Equal(t, str.Expected, addr.String(), "PostalAddress.String() should round-trip")
		})
	}
}
