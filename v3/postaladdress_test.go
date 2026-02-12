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
			Escaped:  `line\5C`,
			Expected: "line\\",
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

			addr, err := NewPostalAddress([]string{str.Expected})
			assert.NoError(t, err)
			assert.Equal(t, str.Expected, addr.String(), "PostalAddress.String() should round-trip")
		})
	}
}

func TestPostalAddressEmptyLines(t *testing.T) {
	_, err := NewPostalAddress([]string{""})
	assert.Equal(t, err, ErrEmptyPostalAddress)
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
			addr, err := NewPostalAddress(tc.lines)
			assert.NoError(t, err)
			escaped := addr.Escape()
			assert.Equal(t, tc.expected, escaped, "UTF-8 characters should be preserved in escaped output")

			// Round-trip test
			parsed, err := ParsePostalAddress(escaped)
			assert.NoError(t, err)
			assert.Equal(t, tc.lines, parsed.Lines(), "UTF-8 characters should survive round-trip")
		})
	}
}

func TestPostalAddressEqual(t *testing.T) {
	testCases := []struct {
		name     string
		addr1    *PostalAddress
		addr2    *PostalAddress
		expected bool
	}{
		{
			name:     "both nil",
			addr1:    nil,
			addr2:    nil,
			expected: true,
		},
		{
			name:     "first nil",
			addr1:    nil,
			addr2:    mustNewPostalAddress(t, []string{"line1"}),
			expected: false,
		},
		{
			name:     "second nil",
			addr1:    mustNewPostalAddress(t, []string{"line1"}),
			addr2:    nil,
			expected: false,
		},
		{
			name:     "same single line",
			addr1:    mustNewPostalAddress(t, []string{"123 Main St"}),
			addr2:    mustNewPostalAddress(t, []string{"123 Main St"}),
			expected: true,
		},
		{
			name:     "different single line",
			addr1:    mustNewPostalAddress(t, []string{"123 Main St"}),
			addr2:    mustNewPostalAddress(t, []string{"456 Oak Ave"}),
			expected: false,
		},
		{
			name:     "same multi-line",
			addr1:    mustNewPostalAddress(t, []string{"123 Main St", "Anytown, CA", "USA"}),
			addr2:    mustNewPostalAddress(t, []string{"123 Main St", "Anytown, CA", "USA"}),
			expected: true,
		},
		{
			name:     "different multi-line content",
			addr1:    mustNewPostalAddress(t, []string{"123 Main St", "Anytown, CA", "USA"}),
			addr2:    mustNewPostalAddress(t, []string{"123 Main St", "Othertown, CA", "USA"}),
			expected: false,
		},
		{
			name:     "different line count",
			addr1:    mustNewPostalAddress(t, []string{"123 Main St", "Anytown, CA"}),
			addr2:    mustNewPostalAddress(t, []string{"123 Main St", "Anytown, CA", "USA"}),
			expected: false,
		},
		{
			name:     "same order matters",
			addr1:    mustNewPostalAddress(t, []string{"line1", "line2"}),
			addr2:    mustNewPostalAddress(t, []string{"line2", "line1"}),
			expected: false,
		},
		{
			name:     "whitespace differences",
			addr1:    mustNewPostalAddress(t, []string{"123 Main St"}),
			addr2:    mustNewPostalAddress(t, []string{"123  Main St"}),
			expected: false,
		},
		{
			name:     "case sensitive",
			addr1:    mustNewPostalAddress(t, []string{"Main Street"}),
			addr2:    mustNewPostalAddress(t, []string{"main street"}),
			expected: false,
		},
		{
			name:     "with special characters",
			addr1:    mustNewPostalAddress(t, []string{"Café René", "$1000\\month"}),
			addr2:    mustNewPostalAddress(t, []string{"Café René", "$1000\\month"}),
			expected: true,
		},
		{
			name:     "with UTF-8 characters",
			addr1:    mustNewPostalAddress(t, []string{"北京市东城区", "中国 🇨🇳"}),
			addr2:    mustNewPostalAddress(t, []string{"北京市东城区", "中国 🇨🇳"}),
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.addr1.Equal(tc.addr2)
			assert.Equal(t, tc.expected, result)

			// Test symmetry (except for nil cases where calling on nil would panic)
			if tc.addr1 != nil && tc.addr2 != nil {
				reverseResult := tc.addr2.Equal(tc.addr1)
				assert.Equal(t, tc.expected, reverseResult, "Equals should be symmetric")
			}
		})
	}
}

func TestParsePostalAddress_Escape(t *testing.T) {
	t.Run("incomplete escape", func(t *testing.T) {
		_, err := ParsePostalAddress("AAAAAAAAAA\\")
		assert.Error(t, err)
	})

	t.Run("invalid escape", func(t *testing.T) {
		_, err := ParsePostalAddress("AAAAAAAAAA\\5XAAAAA")
		assert.Error(t, err)
	})
}

func mustNewPostalAddress(t *testing.T, lines []string) *PostalAddress {
	t.Helper()
	addr, err := NewPostalAddress(lines)
	if err != nil {
		t.Fatalf("NewPostalAddress failed: %v", err)
	}
	return addr
}
