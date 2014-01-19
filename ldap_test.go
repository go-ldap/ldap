package ldap

import (
	"fmt"
	"testing"
)

var ldap_server string = "ldap.itd.umich.edu"
var ldap_port uint16 = 389
var base_dn string = "dc=umich,dc=edu"
var filter []string = []string{
	"(cn=cis-fac)",
	"(&(objectclass=rfc822mailgroup)(cn=*Computer*))",
	"(&(objectclass=rfc822mailgroup)(cn=*Mathematics*))"}
var attributes []string = []string{
	"cn",
	"description"}

func TestConnect(t *testing.T) {
	fmt.Printf("TestConnect: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", ldap_server, ldap_port))
	if err != nil {
		t.Errorf(err.String())
		return
	}
	defer l.Close()
	fmt.Printf("TestConnect: finished...\n")
}

func TestSearch(t *testing.T) {
	fmt.Printf("TestSearch: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", ldap_server, ldap_port))
	if err != nil {
		t.Errorf(err.String())
		return
	}
	defer l.Close()

	search_request := NewSearchRequest(
		base_dn,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[0],
		attributes,
		nil)

	sr, err := l.Search(search_request)
	if err != nil {
		t.Errorf(err.String())
		return
	}

	fmt.Printf("TestSearch: %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))
}

func TestSearchWithPaging(t *testing.T) {
	fmt.Printf("TestSearchWithPaging: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", ldap_server, ldap_port))
	if err != nil {
		t.Errorf(err.String())
		return
	}
	defer l.Close()

	err = l.Bind("", "")
	if err != nil {
		t.Errorf(err.String())
		return
	}

	search_request := NewSearchRequest(
		base_dn,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[1],
		attributes,
		nil)
	sr, err := l.SearchWithPaging(search_request, 5)
	if err != nil {
		t.Errorf(err.String())
		return
	}

	fmt.Printf("TestSearchWithPaging: %s -> num of entries = %d\n", search_request.Filter, len(sr.Entries))
}

func testMultiGoroutineSearch(t *testing.T, l *Conn, results chan *SearchResult, i int) {
	search_request := NewSearchRequest(
		base_dn,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[i],
		attributes,
		nil)
	sr, err := l.Search(search_request)

	if err != nil {
		t.Errorf(err.String())
		results <- nil
		return
	}

	results <- sr
}

func TestMultiGoroutineSearch(t *testing.T) {
	fmt.Printf("TestMultiGoroutineSearch: starting...\n")
	l, err := Dial("tcp", fmt.Sprintf("%s:%d", ldap_server, ldap_port))
	if err != nil {
		t.Errorf(err.String())
		return
	}
	defer l.Close()

	results := make([]chan *SearchResult, len(filter))
	for i := range filter {
		results[i] = make(chan *SearchResult)
		go testMultiGoroutineSearch(t, l, results[i], i)
	}
	for i := range filter {
		sr := <-results[i]
		if sr == nil {
			t.Errorf("Did not receive results from goroutine for %q", filter[i])
		} else {
			fmt.Printf("TestMultiGoroutineSearch(%d): %s -> num of entries = %d\n", i, filter[i], len(sr.Entries))
		}
	}
}
