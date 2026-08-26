package ldap

import (
	"testing"
)

func FuzzParseDN(f *testing.F) {
	f.Add("cn=test,ou=people,o=acme")
	f.Add("cn=test+uid=123,ou=people")
	f.Add("cn=John Doe,dc=example,dc=com")
	f.Add("1.2.3.4=#04024869")
	f.Add("cn=\\ space,ou=people")
	f.Fuzz(func(t *testing.T, dn string) {
		_, _ = ParseDN(dn)
	})
}

func FuzzDecodeEscapedSymbols(f *testing.F) {
	f.Add("test\\,value")
	f.Add("test\\+value")
	f.Add("test\\\"value")
	f.Add("test\\ space")
	f.Add("test\\5cvalue")
	f.Add("test\\\\value")
	f.Add("leading\\,trailing,")
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = decodeString(input)
	})
}

func FuzzEscapeDN(f *testing.F) {
	f.Add("test,value")
	f.Add("test+value")
	f.Add("test\"value")
	f.Add(" test")
	f.Add("test ")
	f.Add("test\\\\value")
	f.Add("normal")
	f.Add("spaces in between")
	f.Fuzz(func(t *testing.T, input string) {
		encodeString(input, true)
		encodeString(input, false)
	})
}
