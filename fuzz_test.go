//go:build go1.18
// +build go1.18

package ldap

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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

func FuzzRoundTripRDNSequence(f *testing.F) {
	f.Add("CN=foo-long.com,OU=FooLong,OU=Barq,OU=Baz,OU=Dept.,O=Corp.,C=US")
	f.Add("CN=foo-lon❤️\\,g.com,OU=Foo===Long,OU=Ba # rq,OU=Baz,O=C\\; orp.,C=US")
	f.Add("CN=fo\x00o-long.com,OU=\x04FooLong")
	f.Add("İ=")

	f.Fuzz(func(t *testing.T, subjectString string) {
		t.Parallel()
		rdnSeq, err := ParseDN(subjectString)
		if err != nil {
			t.Skip()
		}

		newRDNSeq, err := ParseDN(rdnSeq.String())
		if err != nil {
			t.Fatal(err)
		}

		assert.True(t, rdnSeq.Equal(newRDNSeq))
		assert.True(t, rdnSeq.EqualFold(newRDNSeq))
	})
}

func FuzzRoundTripEncodeDecode(f *testing.F) {
	f.Add("dffad=-fasdfsd")
	f.Add("❤️\\,")
	f.Add("aaa\x00o-long.c\x04FooLong")
	f.Add("İ")

	f.Fuzz(func(t *testing.T, rawString string) {
		t.Parallel()
		keyEncoded := encodeString(rawString, true)
		keyDecoded, err := decodeString(keyEncoded)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, rawString, keyDecoded)

		valueEncoded := encodeString(rawString, false)
		valueDecoded, err := decodeString(valueEncoded)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, rawString, valueDecoded)
	})
}
