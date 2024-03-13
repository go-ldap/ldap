//go:build go1.18
// +build go1.18

package ldap

import (
	"os"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

func TestMain(m *testing.M) {
	// For fuzz tests
	// See https://github.com/go-asn1-ber/asn1-ber/blob/04301b4b1c5ff66221f8f8a394f814a9917d678a/fuzz_test.go#L33-L37
	// for why this limitation is necessary
	ber.MaxPacketLengthBytes = 65536

	code := m.Run()
	os.Exit(code)
}

func FuzzParseDN(f *testing.F) {
	f.Add("*")
	f.Add("cn=Jim\\0Test")
	f.Add("cn=Jim\\0")
	f.Add("DC=example,=net")
	f.Add("o=a+o=B")

	f.Fuzz(func(t *testing.T, input_data string) {
		_, _ = ParseDN(input_data)
	})
}

func FuzzDecodeEscapedSymbols(f *testing.F) {

	f.Add([]byte("a\u0100\x80"))
	f.Add([]byte(`start\d`))
	f.Add([]byte(`\`))
	f.Add([]byte(`start\--end`))
	f.Add([]byte(`start\d0\hh`))

	f.Fuzz(func(t *testing.T, input_data []byte) {
		_, _ = decodeEscapedSymbols(input_data)
	})
}

func FuzzEscapeDN(f *testing.F) {

	f.Add("test,user")
	f.Add("#test#user#")
	f.Add("\\test\\user\\")
	f.Add("  test user  ")
	f.Add("\u0000te\x00st\x00user" + string(rune(0)))
	f.Add("test\"+,;<>\\-_user")
	f.Add("test\u0391user ")

	f.Fuzz(func(t *testing.T, input_data string) {
		_ = EscapeDN(input_data)
	})
}
