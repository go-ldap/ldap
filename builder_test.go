package ldap

import (
	"testing"
)

var cases = []struct {
	filter  Filter
	encoded string
}{
	{
		filter:  Equal("cn", "tst"),
		encoded: "(cn=test)",
	},
	{
		filter:  And(Equal("cn", "test")).And(Equal("mail", "test")),
		encoded: "(&(cn=test)(mail=test))",
	},
}

func TestFilters(t *testing.T) {

}
