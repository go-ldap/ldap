package ldap

import (
	"strings"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

type compileTest struct {
	filterStr string

	expectedFilter string
	expectedType   int
	expectedErr    string
}

var testFilters = []compileTest{
	{
		filterStr:      "(&(sn=Miller)(givenName=Bob))",
		expectedFilter: "(&(sn=Miller)(givenName=Bob))",
		expectedType:   FilterAnd,
	},
	{
		filterStr:      "(|(sn=Miller)(givenName=Bob))",
		expectedFilter: "(|(sn=Miller)(givenName=Bob))",
		expectedType:   FilterOr,
	},
	{
		filterStr:      "(!(sn=Miller))",
		expectedFilter: "(!(sn=Miller))",
		expectedType:   FilterNot,
	},
	{
		filterStr:      "(sn=Miller)",
		expectedFilter: "(sn=Miller)",
		expectedType:   FilterEqualityMatch,
	},
	{
		filterStr:      "(sn=Mill*)",
		expectedFilter: "(sn=Mill*)",
		expectedType:   FilterSubstrings,
	},
	{
		filterStr:      "(sn=*Mill)",
		expectedFilter: "(sn=*Mill)",
		expectedType:   FilterSubstrings,
	},
	{
		filterStr:      "(sn=*Mill*)",
		expectedFilter: "(sn=*Mill*)",
		expectedType:   FilterSubstrings,
	},
	{
		filterStr:      "(sn=*i*le*)",
		expectedFilter: "(sn=*i*le*)",
		expectedType:   FilterSubstrings,
	},
	{
		filterStr:      "(sn=Mi*l*r)",
		expectedFilter: "(sn=Mi*l*r)",
		expectedType:   FilterSubstrings,
	},
	// substring filters escape properly
	{
		filterStr:      `(sn=Mi*함*r)`,
		expectedFilter: `(sn=Mi*\ed\95\a8*r)`,
		expectedType:   FilterSubstrings,
	},
	// already escaped substring filters don't get double-escaped
	{
		filterStr:      `(sn=Mi*\ed\95\a8*r)`,
		expectedFilter: `(sn=Mi*\ed\95\a8*r)`,
		expectedType:   FilterSubstrings,
	},
	{
		filterStr:      "(sn=Mi*le*)",
		expectedFilter: "(sn=Mi*le*)",
		expectedType:   FilterSubstrings,
	},
	{
		filterStr:      "(sn=*i*ler)",
		expectedFilter: "(sn=*i*ler)",
		expectedType:   FilterSubstrings,
	},
	{
		filterStr:      "(sn>=Miller)",
		expectedFilter: "(sn>=Miller)",
		expectedType:   FilterGreaterOrEqual,
	},
	{
		filterStr:      "(sn<=Miller)",
		expectedFilter: "(sn<=Miller)",
		expectedType:   FilterLessOrEqual,
	},
	{
		filterStr:      "(sn=*)",
		expectedFilter: "(sn=*)",
		expectedType:   FilterPresent,
	},
	{
		filterStr:      "(sn~=Miller)",
		expectedFilter: "(sn~=Miller)",
		expectedType:   FilterApproxMatch,
	},
	{
		filterStr:      `(objectGUID='\fc\fe\a3\ab\f9\90N\aaGm\d5I~\d12)`,
		expectedFilter: `(objectGUID='\fc\fe\a3\ab\f9\90N\aaGm\d5I~\d12)`,
		expectedType:   FilterEqualityMatch,
	},
	{
		filterStr:      `(objectGUID=абвгдеёжзийклмнопрстуфхцчшщъыьэюя)`,
		expectedFilter: `(objectGUID=\d0\b0\d0\b1\d0\b2\d0\b3\d0\b4\d0\b5\d1\91\d0\b6\d0\b7\d0\b8\d0\b9\d0\ba\d0\bb\d0\bc\d0\bd\d0\be\d0\bf\d1\80\d1\81\d1\82\d1\83\d1\84\d1\85\d1\86\d1\87\d1\88\d1\89\d1\8a\d1\8b\d1\8c\d1\8d\d1\8e\d1\8f)`,
		expectedType:   FilterEqualityMatch,
	},
	{
		filterStr:      `(objectGUID=함수목록)`,
		expectedFilter: `(objectGUID=\ed\95\a8\ec\88\98\eb\aa\a9\eb\a1\9d)`,
		expectedType:   FilterEqualityMatch,
	},
	{
		filterStr:      `(objectGUID=`,
		expectedFilter: ``,
		expectedType:   0,
		expectedErr:    "unexpected end of filter",
	},
	{
		filterStr:      `(objectGUID=함수목록`,
		expectedFilter: ``,
		expectedType:   0,
		expectedErr:    "unexpected end of filter",
	},
	{
		filterStr:      `((cn=)`,
		expectedFilter: ``,
		expectedType:   0,
		expectedErr:    "unexpected end of filter",
	},
	{
		filterStr:      `(&(objectclass=inetorgperson)(cn=中文))`,
		expectedFilter: `(&(objectclass=inetorgperson)(cn=\e4\b8\ad\e6\96\87))`,
		expectedType:   0,
	},
	// attr extension
	{
		filterStr:      `(memberOf:=foo)`,
		expectedFilter: `(memberOf:=foo)`,
		expectedType:   FilterExtensibleMatch,
	},
	// attr+named matching rule extension
	{
		filterStr:      `(memberOf:test:=foo)`,
		expectedFilter: `(memberOf:test:=foo)`,
		expectedType:   FilterExtensibleMatch,
	},
	// attr+oid matching rule extension
	{
		filterStr:      `(cn:1.2.3.4.5:=Fred Flintstone)`,
		expectedFilter: `(cn:1.2.3.4.5:=Fred Flintstone)`,
		expectedType:   FilterExtensibleMatch,
	},
	// attr+dn+oid matching rule extension
	{
		filterStr:      `(sn:dn:2.4.6.8.10:=Barney Rubble)`,
		expectedFilter: `(sn:dn:2.4.6.8.10:=Barney Rubble)`,
		expectedType:   FilterExtensibleMatch,
	},
	// attr+dn extension
	{
		filterStr:      `(o:dn:=Ace Industry)`,
		expectedFilter: `(o:dn:=Ace Industry)`,
		expectedType:   FilterExtensibleMatch,
	},
	// dn extension
	{
		filterStr:      `(:dn:2.4.6.8.10:=Dino)`,
		expectedFilter: `(:dn:2.4.6.8.10:=Dino)`,
		expectedType:   FilterExtensibleMatch,
	},
	{
		filterStr:      `(memberOf:1.2.840.113556.1.4.1941:=CN=User1,OU=blah,DC=mydomain,DC=net)`,
		expectedFilter: `(memberOf:1.2.840.113556.1.4.1941:=CN=User1,OU=blah,DC=mydomain,DC=net)`,
		expectedType:   FilterExtensibleMatch,
	},

	// compileTest{ filterStr: "()", filterType: FilterExtensibleMatch },
}

var testInvalidFilters = []string{
	`(objectGUID=\zz)`,
	`(objectGUID=\a)`,
}

func TestFilter(t *testing.T) {
	// Test Compiler and Decompiler
	for _, i := range testFilters {
		filter, err := CompileFilter(i.filterStr)
		switch {
		case err != nil:
			if i.expectedErr == "" || !strings.Contains(err.Error(), i.expectedErr) {
				t.Errorf("Problem compiling '%s' - '%v' (expected error to contain '%v')", i.filterStr, err, i.expectedErr)
			}
		case filter.Tag != ber.Tag(i.expectedType):
			t.Errorf("%q Expected %q got %q", i.filterStr, FilterMap[uint64(i.expectedType)], FilterMap[uint64(filter.Tag)])
		default:
			o, err := DecompileFilter(filter)
			if err != nil {
				t.Errorf("Problem compiling %s - %s", i.filterStr, err.Error())
			} else if i.expectedFilter != o {
				t.Errorf("%q expected, got %q", i.expectedFilter, o)
			}
		}
	}
}

func TestDecodeEscapedSymbols(t *testing.T) {
	for _, testInfo := range []struct {
		Src string
		Err string
	}{
		{
			Src: "a\u0100\x80",
			Err: `LDAP Result Code 201 "Filter Compile Error": ldap: error reading rune at position 3`,
		},
		{
			Src: `start\d`,
			Err: `LDAP Result Code 201 "Filter Compile Error": ldap: missing characters for escape in filter`,
		},
		{
			Src: `\`,
			Err: `LDAP Result Code 201 "Filter Compile Error": ldap: invalid characters for escape in filter: EOF`,
		},
		{
			Src: `start\--end`,
			Err: `LDAP Result Code 201 "Filter Compile Error": ldap: invalid characters for escape in filter: encoding/hex: invalid byte: U+002D '-'`,
		},
		{
			Src: `start\d0\hh`,
			Err: `LDAP Result Code 201 "Filter Compile Error": ldap: invalid characters for escape in filter: encoding/hex: invalid byte: U+0068 'h'`,
		},
	} {

		res, err := decodeEscapedSymbols([]byte(testInfo.Src))
		if err == nil || err.Error() != testInfo.Err {
			t.Fatal(testInfo.Src, "=> ", err, "!=", testInfo.Err)
		}
		if res != "" {
			t.Fatal(testInfo.Src, "=> ", "invalid result", res)
		}
	}
}

func TestInvalidFilter(t *testing.T) {
	for _, filterStr := range testInvalidFilters {
		if _, err := CompileFilter(filterStr); err == nil {
			t.Errorf("Problem compiling %s - expected err", filterStr)
		}
	}
}

func TestDecompileFilterEscapesAttribute(t *testing.T) {
	eq := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterEqualityMatch, nil, FilterMap[FilterEqualityMatch])
	eq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "uid)(uid=admin", "Attribute"))
	eq.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "x", "Condition"))

	got, err := DecompileFilter(eq)
	if err != nil {
		t.Fatal(err)
	}
	if want := `(uid\29\28uid=admin=x)`; got != want {
		t.Errorf("equality attribute not escaped: got %q want %q", got, want)
	}

	em := ber.Encode(ber.ClassContext, ber.TypeConstructed, FilterExtensibleMatch, nil, FilterMap[FilterExtensibleMatch])
	em.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, MatchingRuleAssertionMatchingRule, "1)(x=*", MatchingRuleAssertionMap[MatchingRuleAssertionMatchingRule]))
	em.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, MatchingRuleAssertionType, "cn*evil", MatchingRuleAssertionMap[MatchingRuleAssertionType]))
	em.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, MatchingRuleAssertionMatchValue, "v", MatchingRuleAssertionMap[MatchingRuleAssertionMatchValue]))

	got, err = DecompileFilter(em)
	if err != nil {
		t.Fatal(err)
	}
	if want := `(cn\2aevil:1\29\28x=\2a:=v)`; got != want {
		t.Errorf("extensible match attribute/rule not escaped: got %q want %q", got, want)
	}
}

func BenchmarkFilterCompile(b *testing.B) {
	b.StopTimer()
	filters := make([]string, len(testFilters))

	// Test Compiler and Decompiler
	for idx, i := range testFilters {
		filters[idx] = i.filterStr
	}

	maxIdx := len(filters)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, _ = CompileFilter(filters[i%maxIdx])
	}
}

func BenchmarkFilterDecompile(b *testing.B) {
	b.StopTimer()
	filters := make([]*ber.Packet, len(testFilters))

	// Test Compiler and Decompiler
	for idx, i := range testFilters {
		filters[idx], _ = CompileFilter(i.filterStr)
	}

	maxIdx := len(filters)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecompileFilter(filters[i%maxIdx])
	}
}

func TestHegelPinFilterClosingParenChecked(t *testing.T) {
	for _, filterStr := range []string{
		`(&(a=b)x`,
		`(!(a=b)x`,
		`((a=b)x`,
		`(|(a=b)]`,
		`(&(a=b)(c=d)x`,
		`(!(a=b)`,
		`((a=b)`,
		`(&x)`,
	} {
		if _, err := CompileFilter(filterStr); err == nil {
			t.Errorf("CompileFilter(%q) expected error, got nil", filterStr)
		} else if !strings.Contains(err.Error(), "unexpected end of filter") {
			t.Errorf("CompileFilter(%q) error %q does not contain %q", filterStr, err, "unexpected end of filter")
		}
	}

	// Properly closed nested filters must keep compiling (redundant wrapping
	// parentheses are dropped, as before).
	for _, tc := range []struct{ in, want string }{
		{`((a=b))`, `(a=b)`},
		{`(!(!(a=b)))`, `(!(!(a=b)))`},
		{`(|(&(a=b))(c=d))`, `(|(&(a=b))(c=d))`},
		{`(&(|(a=b)(c=d))(!(e=f)))`, `(&(|(a=b)(c=d))(!(e=f)))`},
	} {
		p, err := CompileFilter(tc.in)
		if err != nil {
			t.Fatalf("CompileFilter(%q) unexpected error: %v", tc.in, err)
		}
		got, err := DecompileFilter(p)
		if err != nil {
			t.Fatalf("DecompileFilter(%q) unexpected error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Errorf("decompile of %q = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHegelPinEmptySubstringsRejected(t *testing.T) {
	for _, filterStr := range []string{`(sn=**)`, `(sn=***)`} {
		if _, err := CompileFilter(filterStr); err == nil {
			t.Errorf("CompileFilter(%q) expected error, got nil", filterStr)
		}
	}

	// "*" alone is the present filter and must keep working.
	present, err := CompileFilter(`(sn=*)`)
	if err != nil {
		t.Fatalf("CompileFilter(%q) unexpected error: %v", `(sn=*)`, err)
	}
	if present.Tag != FilterPresent {
		t.Errorf("(sn=*) expected FilterPresent, got %s", FilterMap[uint64(present.Tag)])
	}

	// Ordinary substring filters still round-trip.
	for _, filterStr := range []string{`(sn=*Mill)`, `(sn=Mill*)`, `(sn=*Mill*)`, `(sn=Mi*l*r)`} {
		p, err := CompileFilter(filterStr)
		if err != nil {
			t.Fatalf("CompileFilter(%q) unexpected error: %v", filterStr, err)
		}
		got, err := DecompileFilter(p)
		if err != nil {
			t.Fatalf("DecompileFilter(%q) unexpected error: %v", filterStr, err)
		}
		if got != filterStr {
			t.Errorf("round trip of %q = %q", filterStr, got)
		}
	}
}

func TestHegelPinDnattrsCaseInsensitive(t *testing.T) {
	for _, filterStr := range []string{`(o:DN:=x)`, `(o:Dn:=x)`, `(o:dN:=x)`, `(o:dn:=x)`} {
		p, err := CompileFilter(filterStr)
		if err != nil {
			t.Fatalf("CompileFilter(%q) unexpected error: %v", filterStr, err)
		}
		got, err := DecompileFilter(p)
		if err != nil {
			t.Fatalf("DecompileFilter(%q) unexpected error: %v", filterStr, err)
		}
		if want := `(o:dn:=x)`; got != want {
			t.Errorf("CompileFilter(%q) decompiled as %q, want %q", filterStr, got, want)
		}
	}

	// A matching rule after a case-insensitive :DN: marker is still recognised.
	p, err := CompileFilter(`(sn:DN:2.4.6.8.10:=x)`)
	if err != nil {
		t.Fatalf("CompileFilter unexpected error: %v", err)
	}
	if got, _ := DecompileFilter(p); got != `(sn:dn:2.4.6.8.10:=x)` {
		t.Errorf("(sn:DN:...) decompiled as %q", got)
	}
}

func TestHegelPinReplacementCharCompiles(t *testing.T) {
	// A literal U+FFFD (EF BF BD) is a valid UTF-8 character and must compile.
	p, err := CompileFilter("(cn=a\uFFFDb)")
	if err != nil {
		t.Fatalf("CompileFilter with literal U+FFFD: %v", err)
	}
	got, err := DecompileFilter(p)
	if err != nil {
		t.Fatalf("DecompileFilter with literal U+FFFD: %v", err)
	}
	if want := `(cn=a\ef\bf\bdb)`; got != want {
		t.Errorf("literal U+FFFD decompiled as %q, want %q", got, want)
	}

	// Genuinely invalid UTF-8 is still rejected.
	if _, err := CompileFilter("(cn=a\xffb)"); err == nil {
		t.Error("CompileFilter with invalid UTF-8 expected error, got nil")
	}
}

func TestHegelPinAttributeDescriptionValidated(t *testing.T) {
	for _, filterStr := range []string{`(=v)`, `(a b=v)`, `(a\2ab=v)`, `(1.2.3.=v)`, `(a;=v)`, `(-cn=v)`, `(a b:=v)`} {
		if _, err := CompileFilter(filterStr); err == nil {
			t.Errorf("CompileFilter(%q) expected error, got nil", filterStr)
		}
	}

	// Valid descr, numericoid and options must keep compiling.
	for _, filterStr := range []string{`(cn=v)`, `(1.2.3=v)`, `(cn;lang-en=v)`, `(cn;123=v)`, `(cn;-x=v)`, `(1.2.3;binary=v)`, `(objectClass=*)`} {
		if _, err := CompileFilter(filterStr); err != nil {
			t.Errorf("CompileFilter(%q) unexpected error: %v", filterStr, err)
		}
	}
}
