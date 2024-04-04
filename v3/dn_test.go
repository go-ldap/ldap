package ldap

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSuccessfulDNParsing(t *testing.T) {
	testcases := map[string]DN{
		"": {[]*RelativeDN{}},
		"cn=Jim\\2C \\22Hasse Hö\\22 Hansson!,dc=dummy,dc=com": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"cn", "Jim, \"Hasse Hö\" Hansson!"}}},
			{[]*AttributeTypeAndValue{{"dc", "dummy"}}},
			{[]*AttributeTypeAndValue{{"dc", "com"}}},
		}},
		"UID=jsmith,DC=example,DC=net": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"UID", "jsmith"}}},
			{[]*AttributeTypeAndValue{{"DC", "example"}}},
			{[]*AttributeTypeAndValue{{"DC", "net"}}},
		}},
		"OU=Sales+CN=J. Smith,DC=example,DC=net": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{
				{"OU", "Sales"},
				{"CN", "J. Smith"},
			}},
			{[]*AttributeTypeAndValue{{"DC", "example"}}},
			{[]*AttributeTypeAndValue{{"DC", "net"}}},
		}},
		"1.3.6.1.4.1.1466.0=#04024869": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"1.3.6.1.4.1.1466.0", "Hi"}}},
		}},
		"1.3.6.1.4.1.1466.0=#04024869,DC=net": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"1.3.6.1.4.1.1466.0", "Hi"}}},
			{[]*AttributeTypeAndValue{{"DC", "net"}}},
		}},
		"CN=Lu\\C4\\8Di\\C4\\87": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"CN", "Lučić"}}},
		}},
		"  CN  =  Lu\\C4\\8Di\\C4\\87  ": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"CN", "Lučić"}}},
		}},
		`   A   =   1   ,   B   =   2   `: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"A", "1"}}},
			{[]*AttributeTypeAndValue{{"B", "2"}}},
		}},
		`   A   =   1   +   B   =   2   `: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{
				{"A", "1"},
				{"B", "2"},
			}},
		}},
		`   \ \ A\ \    =   \ \ 1\ \    ,   \ \ B\ \    =   \ \ 2\ \    `: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"  A  ", "  1  "}}},
			{[]*AttributeTypeAndValue{{"  B  ", "  2  "}}},
		}},
		`   \ \ A\ \    =   \ \ 1\ \    +   \ \ B\ \    =   \ \ 2\ \    `: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{
				{"  A  ", "  1  "},
				{"  B  ", "  2  "},
			}},
		}},
		"A = 88  \t": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{
				{"A", "88  \t"},
			}},
		}},
		"A = 88  \n": {[]*RelativeDN{
			{[]*AttributeTypeAndValue{
				{"A", "88  \n"},
			}},
		}},
		`cn=john.doe;dc=example,dc=net`: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"cn", "john.doe"}}},
			{[]*AttributeTypeAndValue{{"dc", "example"}}},
			{[]*AttributeTypeAndValue{{"dc", "net"}}},
		}},
		`cn=⭐;dc=❤️=\==,dc=❤️\\`: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"cn", "⭐"}}},
			{[]*AttributeTypeAndValue{{"dc", "❤️==="}}},
			{[]*AttributeTypeAndValue{{"dc", "❤️\\"}}},
		}},

		// Escaped `;` should not be treated as RDN
		`cn=john.doe\;weird name,dc=example,dc=net`: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"cn", "john.doe;weird name"}}},
			{[]*AttributeTypeAndValue{{"dc", "example"}}},
			{[]*AttributeTypeAndValue{{"dc", "net"}}},
		}},
		`cn=ZXhhbXBsZVRleHQ=,dc=dummy,dc=com`: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"cn", "ZXhhbXBsZVRleHQ="}}},
			{[]*AttributeTypeAndValue{{"dc", "dummy"}}},
			{[]*AttributeTypeAndValue{{"dc", "com"}}},
		}},
		`1.3.6.1.4.1.1466.0=test`: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"1.3.6.1.4.1.1466.0", "test"}}},
		}},
		`1=#04024869`: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"1", "Hi"}}},
		}},
		`CN=James \"Jim\" Smith\, III,DC=example,DC=net`: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"CN", "James \"Jim\" Smith, III"}}},
			{[]*AttributeTypeAndValue{{"DC", "example"}}},
			{[]*AttributeTypeAndValue{{"DC", "net"}}},
		}},
		`CN=Before\0dAfter,DC=example,DC=net`: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"CN", "Before\x0dAfter"}}},
			{[]*AttributeTypeAndValue{{"DC", "example"}}},
			{[]*AttributeTypeAndValue{{"DC", "net"}}},
		}},
		`cn=foo-lon\e2\9d\a4\ef\b8\8f\,g.com,OU=Foo===Long;ou=Ba # rq,ou=Baz,o=C\; orp.+c=US`: {[]*RelativeDN{
			{[]*AttributeTypeAndValue{{"cn", "foo-lon❤️,g.com"}}},
			{[]*AttributeTypeAndValue{{"OU", "Foo===Long"}}},
			{[]*AttributeTypeAndValue{{"ou", "Ba # rq"}}},
			{[]*AttributeTypeAndValue{{"ou", "Baz"}}},
			{[]*AttributeTypeAndValue{{"o", "C; orp."}, {"c", "US"}}},
		}},
	}

	for test, answer := range testcases {
		dn, err := ParseDN(test)
		if err != nil {
			t.Errorf("ParseDN failed for DN test '%s': %s", test, err)
			continue
		}
		if !reflect.DeepEqual(dn, &answer) {
			t.Errorf("Parsed DN '%s' is not equal to the expected structure", test)
			t.Logf("Expected:")
			for _, rdn := range answer.RDNs {
				for _, attribute := range rdn.Attributes {
					t.Logf("	#%v\n", attribute)
				}
			}
			t.Logf("Actual:")
			for _, rdn := range dn.RDNs {
				for _, attribute := range rdn.Attributes {
					t.Logf("	#%v\n", attribute)
				}
			}
		}
	}
}

func TestErrorDNParsing(t *testing.T) {
	testcases := map[string]string{
		"*":                         "DN ended with incomplete type, value pair",
		"cn=Jim\\0Test":             "failed to decode escaped character: encoding/hex: invalid byte: U+0054 'T'",
		"cn=Jim\\0":                 "failed to decode escaped character: encoding/hex: invalid byte: 0",
		"DC=example,=net":           "DN ended with incomplete type, value pair",
		"1=#0402486":                "failed to decode BER encoding: encoding/hex: odd length hex string",
		"test,DC=example,DC=com":    "incomplete type, value pair",
		"=test,DC=example,DC=com":   "incomplete type, value pair",
		"1.3.6.1.4.1.1466.0=test+":  "DN ended with incomplete type, value pair",
		`1.3.6.1.4.1.1466.0=test;`:  "DN ended with incomplete type, value pair",
		"1.3.6.1.4.1.1466.0=test+,": "incomplete type, value pair",
		"DF=#6666666666665006838820013100000746939546349182108463491821809FBFFFFFFFFF": "failed to unmarshal hex-encoded string: asn1: syntax error: data truncated",
	}

	for test, answer := range testcases {
		_, err := ParseDN(test)
		if err == nil {
			t.Errorf("Expected '%s' to fail parsing but succeeded\n", test)
		} else if err.Error() != answer {
			t.Errorf("Unexpected error on: '%s':\nExpected:	%s\nGot:		%s\n", test, answer, err.Error())
		}
	}
}

func TestDNEqual(t *testing.T) {
	testcases := []struct {
		A     string
		B     string
		Equal bool
	}{
		// Exact match
		{"", "", true},
		{"o=A", "o=A", true},
		{"o=A", "o=B", false},

		{"o=A,o=B", "o=A,o=B", true},
		{"o=A,o=B", "o=A,o=C", false},

		{"o=A+o=B", "o=A+o=B", true},
		{"o=A+o=B", "o=A+o=C", false},

		// Case mismatch in type is ignored
		{"o=A", "O=A", true},
		{"o=A,o=B", "o=A,O=B", true},
		{"o=A+o=B", "o=A+O=B", true},

		// Case mismatch in value is significant
		{"o=a", "O=A", false},
		{"o=a,o=B", "o=A,O=B", false},
		{"o=a+o=B", "o=A+O=B", false},

		// Multi-valued RDN order mismatch is ignored
		{"o=A+o=B", "O=B+o=A", true},
		// Number of RDN attributes is significant
		{"o=A+o=B", "O=B+o=A+O=B", false},

		// Missing values are significant
		{"o=A+o=B", "O=B+o=A+O=C", false}, // missing values matter
		{"o=A+o=B+o=C", "O=B+o=A", false}, // missing values matter

		// Whitespace tests
		// Matching
		{
			"cn=John Doe, ou=People, dc=sun.com",
			"cn=John Doe, ou=People, dc=sun.com",
			true,
		},
		// Difference in leading/trailing chars is ignored
		{
			"cn=\\ John\\20Doe, ou=People, dc=sun.com",
			"cn= \\ John Doe,ou=People,dc=sun.com",
			true,
		},
		// Difference in values is significant
		{
			"cn=John Doe, ou=People, dc=sun.com",
			"cn=John  Doe, ou=People, dc=sun.com",
			false,
		},
		// Test parsing of `;` for separating RDNs
		{"cn=john;dc=example,dc=com", "cn=john,dc=example,dc=com", true}, // missing values matter
	}

	for i, tc := range testcases {
		a, err := ParseDN(tc.A)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		b, err := ParseDN(tc.B)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		if expected, actual := tc.Equal, a.Equal(b); expected != actual {
			t.Errorf("%d: when comparing %q and %q expected %v, got %v", i, a, b, expected, actual)
			continue
		}
		if expected, actual := tc.Equal, b.Equal(a); expected != actual {
			t.Errorf("%d: when comparing %q and %q expected %v, got %v", i, a, b, expected, actual)
			continue
		}

		if expected, actual := a.Equal(b), a.String() == b.String(); expected != actual {
			t.Errorf("%d: when asserting string comparison of %q and %q expected equal %v, got %v", i, a, b, expected, actual)
			continue
		}
	}
}

func TestDNEqualFold(t *testing.T) {
	testcases := []struct {
		A     string
		B     string
		Equal bool
	}{
		// Match on case insensitive
		{"o=A", "o=a", true},
		{"o=A,o=b", "o=a,o=B", true},
		{"o=a+o=B", "o=A+o=b", true},
		{
			"cn=users,ou=example,dc=com",
			"cn=Users,ou=example,dc=com",
			true,
		},

		// Match on case insensitive and case mismatch in type
		{"o=A", "O=a", true},
		{"o=A,o=b", "o=a,O=B", true},
		{"o=a+o=B", "o=A+O=b", true},
	}

	for i, tc := range testcases {
		a, err := ParseDN(tc.A)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		b, err := ParseDN(tc.B)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		if expected, actual := tc.Equal, a.EqualFold(b); expected != actual {
			t.Errorf("%d: when comparing '%s' and '%s' expected %v, got %v", i, tc.A, tc.B, expected, actual)
			continue
		}
		if expected, actual := tc.Equal, b.EqualFold(a); expected != actual {
			t.Errorf("%d: when comparing '%s' and '%s' expected %v, got %v", i, tc.A, tc.B, expected, actual)
			continue
		}
	}
}

func TestDNAncestor(t *testing.T) {
	testcases := []struct {
		A        string
		B        string
		Ancestor bool
	}{
		// Exact match returns false
		{"", "", false},
		{"o=A", "o=A", false},
		{"o=A,o=B", "o=A,o=B", false},
		{"o=A+o=B", "o=A+o=B", false},

		// Mismatch
		{"ou=C,ou=B,o=A", "ou=E,ou=D,ou=B,o=A", false},

		// Descendant
		{"ou=C,ou=B,o=A", "ou=E,ou=C,ou=B,o=A", true},
	}

	for i, tc := range testcases {
		a, err := ParseDN(tc.A)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		b, err := ParseDN(tc.B)
		if err != nil {
			t.Errorf("%d: %v", i, err)
			continue
		}
		if expected, actual := tc.Ancestor, a.AncestorOf(b); expected != actual {
			t.Errorf("%d: when comparing '%s' and '%s' expected %v, got %v", i, tc.A, tc.B, expected, actual)
			continue
		}
	}
}

func BenchmarkParseSubject(b *testing.B) {
	for n := 0; n < b.N; n++ {
		_, err := ParseDN("DF=#6666666666665006838820013100000746939546349182108463491821809FBFFFFFFFFF")
		if err == nil {
			b.Fatal("expected error, but got none")
		}
	}
}

func TestMustKeepOrderInRawDerBytes(t *testing.T) {
	subject := "cn=foo-long.com,ou=FooLong,ou=Barq,ou=Baz,ou=Dept.,o=Corp.,c=US"
	rdnSeq, err := ParseDN(subject)
	if err != nil {
		t.Fatal(err)
	}

	expectedRdnSeq := &DN{
		[]*RelativeDN{
			{[]*AttributeTypeAndValue{{Type: "cn", Value: "foo-long.com"}}},
			{[]*AttributeTypeAndValue{{Type: "ou", Value: "FooLong"}}},
			{[]*AttributeTypeAndValue{{Type: "ou", Value: "Barq"}}},
			{[]*AttributeTypeAndValue{{Type: "ou", Value: "Baz"}}},
			{[]*AttributeTypeAndValue{{Type: "ou", Value: "Dept."}}},
			{[]*AttributeTypeAndValue{{Type: "o", Value: "Corp."}}},
			{[]*AttributeTypeAndValue{{Type: "c", Value: "US"}}},
		},
	}

	assert.Equal(t, expectedRdnSeq, rdnSeq)
	assert.Equal(t, subject, rdnSeq.String())
}

func TestRoundTripLiteralSubject(t *testing.T) {
	rdnSequences := map[string]string{
		"cn=foo-long.com,ou=FooLong,ou=Barq,ou=Baz,ou=Dept.,o=Corp.,c=US":       "cn=foo-long.com,ou=FooLong,ou=Barq,ou=Baz,ou=Dept.,o=Corp.,c=US",
		"cn=foo-lon❤️\\,g.com,ou=Foo===Long,ou=Ba # rq,ou=Baz,o=C\\; orp.,c=US": "cn=foo-lon\\e2\\9d\\a4\\ef\\b8\\8f\\,g.com,ou=Foo===Long,ou=Ba # rq,ou=Baz,o=C\\; orp.,c=US",
		"cn=fo\x00o-long.com,ou=\x04FooLong":                                    "cn=fo\\00o-long.com,ou=\\04FooLong",
	}

	for subjIn, subjOut := range rdnSequences {
		t.Logf("Testing subject: %s", subjIn)

		newRDNSeq, err := ParseDN(subjIn)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, subjOut, newRDNSeq.String())
	}
}

func TestDecodeString(t *testing.T) {
	successTestcases := map[string]string{
		"foo-long.com":      "foo-long.com",
		"foo-lon❤️\\,g.com": "foo-lon❤️,g.com",
		"fo\x00o-long.com":  "fo\x00o-long.com",
		"fo\\00o-long.com":  "fo\x00o-long.com",
	}

	for encoded, decoded := range successTestcases {
		t.Logf("Testing encoded string: %s", encoded)
		decodedString, err := decodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, decoded, decodedString)
	}

	errorTestcases := map[string]string{
		"fo\\":              "got corrupted escaped character: 'fo\\'",
		"fo\\0":             "failed to decode escaped character: encoding/hex: invalid byte: 0",
		"fo\\UU️o-long.com": "failed to decode escaped character: encoding/hex: invalid byte: U+0055 'U'",
		"fo\\0❤️o-long.com": "failed to decode escaped character: invalid byte: 0❤",
	}

	for encoded, expectedError := range errorTestcases {
		t.Logf("Testing encoded string: %s", encoded)
		_, err := decodeString(encoded)
		assert.EqualError(t, err, expectedError)
	}
}
