package ldap

import (
	"testing"
)

var cases = []struct {
	filter  Filter
	encoded string
}{
	{
		filter:  Equal("cn", "test"),
		encoded: "(cn=test)",
	},
	{
		filter:  And(Equal("cn", "test")).And(Equal("mail", "test")),
		encoded: "(&(cn=test)(mail=test))",
	},
	{
		filter: And(Equal("cn", "test")).
			And(Equal("mail", "test")).
			And(Equal("sn", "test")),
		encoded: "(&(cn=test)(mail=test)(sn=test))",
	},
	{
		filter:  Or(Equal("cn", "test")).Or(Equal("cn", "other_test")),
		encoded: "(|(cn=test)(cn=other_test))",
	},
	{
		filter: Or(Equal("cn", "test")).
			Or(Equal("mail", "test")).
			Or(Equal("sn", "test")),
		encoded: "(|(cn=test)(mail=test)(sn=test))",
	},
	{
		filter:  Not(Equal("cn", "test")),
		encoded: "(!(cn=test))",
	},
	{
		filter:  Substrings("cn", "", []string{}, "test"),
		encoded: "(cn=*test)",
	},
	{
		filter:  Substrings("cn", "", []string{"test", "test"}, ""),
		encoded: "(cn=*test*test*)",
	},
	{
		filter:  Substrings("cn", "test", []string{}, "test"),
		encoded: "(cn=test*test)",
	},
	{
		filter:  Substrings("cn", "test", []string{"test", "test"}, "test"),
		encoded: "(cn=test*test*test*test)",
	},
	{
		filter:  GreaterOrEqual("counter", "1"),
		encoded: "(counter>=1)",
	},
	{
		filter:  ApproximateMatch("cn", "test"),
		encoded: "(cn~=test)",
	},
	{
		filter:  Present("cn"),
		encoded: "(cn=*)",
	},
	{
		filter:  LessOrEqual("cn", "test"),
		encoded: "(cn<=test)",
	},
	{
		filter:  ExtensibleMatch("cn", true, "rule", "test"),
		encoded: "(cn:dn:rule:=test)",
	},
	{
		filter:  ExtensibleMatch("cn", false, "", "test"),
		encoded: "(cn:=test)",
	},
	{
		filter:  ExtensibleMatch("", true, "", "test"),
		encoded: "(:dn:=test)",
	},
	{
		filter:  Equal("c)n", "te)st"),
		encoded: "(c\\29n=te\\29st)",
	},
	{
		filter:  Substrings("c)n", "))", []string{"tes)t", "tes)t"}, "test)"),
		encoded: "(c\\29n=\\29\\29*tes\\29t*tes\\29t*test\\29)",
	},
	{
		filter:  GreaterOrEqual("c(n", "test("),
		encoded: "(c\\28n>=test\\28)",
	},
	{
		filter:  LessOrEqual("c(n", "test("),
		encoded: "(c\\28n<=test\\28)",
	},
	{
		filter:  ApproximateMatch("c(n", "test("),
		encoded: "(c\\28n~=test\\28)",
	},
	{
		filter:  Present("c(n"),
		encoded: "(c\\28n=*)",
	},
	{
		filter:  ExtensibleMatch("c(n", true, "test(", "tes)t"),
		encoded: "(c\\28n:dn:test\\28:=tes\\29t)",
	},
}

func TestFilters(t *testing.T) {
	for _, cas := range cases {
		if cas.encoded != cas.filter.String() {
			t.Errorf("Expected %s but got %s", cas.encoded, cas.filter.String())
		}
	}
}
