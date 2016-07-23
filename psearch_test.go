package ldap_test

import (
	"crypto/tls"
	"fmt"
	"gopkg.in/ldap.v2"
)

func ExamplePersistentSearch() {
	l, err := ldap.DialTLS("tcp", "ldap.example.org:636", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		panic("DialTLS: " + err.Error())
	}
	_, err = l.SimpleBind(ldap.NewSimpleBindRequest("uid=someone,dc=example,dc=org", "MySecret", nil))
	if err != nil {
		panic("SimpleBind(): " + err.Error())
	}
	req := &ldap.SearchRequest{
		BaseDN:     "ou=people,dc=example,dc=org",
		Scope:      ldap.ScopeWholeSubtree,
		Filter:     "(uid=*)",
		Attributes: []string{"uid", "cn"},
	}
	l.Debug = true
	err = l.PersistentSearch(req, []string{"any"}, true, true, callBack)
	if err != nil {
		panic("PersistentSearch(): " + err.Error())
	}
}

func callBack(res *ldap.SearchResult) bool {
	if len(res.Entries) != 0 {
		entry := res.Entries[0]
		fmt.Printf("%s (%s)\n", entry.GetAttributeValue("cn"), entry.GetAttributeValue("uid"))
	}
	if len(res.Controls) != 0 {
		fmt.Printf("CTRL=%s\n", res.Controls[0].String())
	}
	return true
}
