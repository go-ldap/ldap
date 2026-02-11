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
			Escaped:  "AAAAA\\5cBBBBB$",
			Expected: "AAAAA\\BBBBB",
		},
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

func TestPostalAddressUTF8Handling(t *testing.T) {
	testCases := []struct {
		name     string
		lines    []string
		expected string
	}{
		{
			name:     "emoji characters",
			lines:    []string{"123 Main St 🏠", "Tokyo 🗾", "Japan 🇯🇵"},
			expected: "123 Main St 🏠$Tokyo 🗾$Japan 🇯🇵$",
		},
		{
			name:     "cyrillic characters",
			lines:    []string{"Красная площадь", "Москва 101000", "Россия"},
			expected: "Красная площадь$Москва 101000$Россия$",
		},
		{
			name:     "chinese characters",
			lines:    []string{"北京市东城区", "天安门广场", "中国"},
			expected: "北京市东城区$天安门广场$中国$",
		},
		{
			name:     "arabic characters",
			lines:    []string{"شارع الملك فهد", "الرياض", "المملكة العربية السعودية"},
			expected: "شارع الملك فهد$الرياض$المملكة العربية السعودية$",
		},
		{
			name:     "mixed scripts with special chars",
			lines:    []string{"Café René ☕", "Zürich $1000\\month", "Schweiz 🇨🇭"},
			expected: "Café René ☕$Zürich \\241000\\5Cmonth$Schweiz 🇨🇭$",
		},
		{
			name:     "mathematical symbols",
			lines:    []string{"∑ ∫ ∂", "π ≈ 3.14159", "∞ ≠ 0"},
			expected: "∑ ∫ ∂$π ≈ 3.14159$∞ ≠ 0$",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			addr := NewPostalAddress(tc.lines)
			escaped := addr.Escape()
			assert.Equal(t, tc.expected, escaped, "UTF-8 characters should be preserved in escaped output")

			// Round-trip test
			parsed, err := ParsePostalAddress(escaped)
			assert.NoError(t, err)
			assert.Equal(t, tc.lines, parsed.Lines(), "UTF-8 characters should survive round-trip")
		})
	}
}
