package ldap

import (
	"crypto/tls"
	"testing"
)

const ldapServer = "ldap://ldap.itd.umich.edu:389"
const ldapsServer = "ldaps://ldap.itd.umich.edu:636"
const baseDN = "dc=umich,dc=edu"

var filter = []string{
	"(cn=cis-fac)",
	"(&(owner=*)(cn=cis-fac))",
	"(&(objectclass=rfc822mailgroup)(cn=*Computer*))",
	"(&(objectclass=rfc822mailgroup)(cn=*Mathematics*))"}
var attributes = []string{
	"cn",
	"description"}

func TestUnsecureDialURL(t *testing.T) {
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
}

func TestSecureDialURL(t *testing.T) {
	l, err := DialURL(ldapsServer, DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
}

func TestStartTLS(t *testing.T) {
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTLSConnectionState(t *testing.T) {
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}

	cs, ok := l.TLSConnectionState()
	if !ok {
		t.Errorf("TLSConnectionState returned ok == false; want true")
	}
	if cs.Version == 0 || !cs.HandshakeComplete {
		t.Errorf("ConnectionState = %#v; expected Version != 0 and HandshakeComplete = true", cs)
	}
}

func TestSearch(t *testing.T) {
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	searchRequest := NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[0],
		attributes,
		nil)

	sr, err := l.Search(searchRequest)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("TestSearch: %s -> num of entries = %d", searchRequest.Filter, len(sr.Entries))
}

func TestSearchStartTLS(t *testing.T) {
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	searchRequest := NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[0],
		attributes,
		nil)

	sr, err := l.Search(searchRequest)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("TestSearchStartTLS: %s -> num of entries = %d", searchRequest.Filter, len(sr.Entries))

	t.Log("TestSearchStartTLS: upgrading with startTLS")
	err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}

	sr, err = l.Search(searchRequest)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("TestSearchStartTLS: %s -> num of entries = %d", searchRequest.Filter, len(sr.Entries))
}

func TestSearchWithPaging(t *testing.T) {
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	err = l.UnauthenticatedBind("")
	if err != nil {
		t.Fatal(err)
	}

	searchRequest := NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[2],
		attributes,
		nil)
	sr, err := l.SearchWithPaging(searchRequest, 5)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("TestSearchWithPaging: %s -> num of entries = %d", searchRequest.Filter, len(sr.Entries))

	searchRequest = NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[2],
		attributes,
		[]Control{NewControlPaging(5)})
	sr, err = l.SearchWithPaging(searchRequest, 5)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("TestSearchWithPaging: %s -> num of entries = %d", searchRequest.Filter, len(sr.Entries))

	searchRequest = NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[2],
		attributes,
		[]Control{NewControlPaging(500)})
	sr, err = l.SearchWithPaging(searchRequest, 5)
	if err == nil {
		t.Fatal("expected an error when paging size in control in search request doesn't match size given in call, got none")
	}
}

func searchGoroutine(t *testing.T, l *Conn, results chan *SearchResult, i int) {
	searchRequest := NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[i],
		attributes,
		nil)
	sr, err := l.Search(searchRequest)
	if err != nil {
		t.Error(err)
		results <- nil
		return
	}
	results <- sr
}

func testMultiGoroutineSearch(t *testing.T, TLS bool, startTLS bool) {
	var l *Conn
	var err error
	if TLS {
		l, err = DialURL(ldapsServer, DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
	} else {
		l, err = DialURL(ldapServer)
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		if startTLS {
			t.Log("TestMultiGoroutineSearch: using StartTLS...")
			err := l.StartTLS(&tls.Config{InsecureSkipVerify: true})
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	results := make([]chan *SearchResult, len(filter))
	for i := range filter {
		results[i] = make(chan *SearchResult)
		go searchGoroutine(t, l, results[i], i)
	}
	for i := range filter {
		sr := <-results[i]
		if sr == nil {
			t.Errorf("Did not receive results from goroutine for %q", filter[i])
		} else {
			t.Logf("TestMultiGoroutineSearch(%d): %s -> num of entries = %d", i, filter[i], len(sr.Entries))
		}
	}
}

func TestMultiGoroutineSearch(t *testing.T) {
	testMultiGoroutineSearch(t, false, false)
	testMultiGoroutineSearch(t, true, true)
	testMultiGoroutineSearch(t, false, true)
}

func TestEscapeFilter(t *testing.T) {
	if got, want := EscapeFilter("a\x00b(c)d*e\\f"), `a\00b\28c\29d\2ae\5cf`; got != want {
		t.Errorf("Got %s, expected %s", want, got)
	}
	if got, want := EscapeFilter("Lučić"), `Lu\c4\8di\c4\87`; got != want {
		t.Errorf("Got %s, expected %s", want, got)
	}
}

func TestCompare(t *testing.T) {
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	const dn = "cn=math mich,ou=User Groups,ou=Groups,dc=umich,dc=edu"
	const attribute = "cn"
	const value = "math mich"

	sr, err := l.Compare(dn, attribute, value)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Compare result:", sr)
}

func TestMatchDNError(t *testing.T) {
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	const wrongBase = "ou=roups,dc=umich,dc=edu"

	searchRequest := NewSearchRequest(
		wrongBase,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[0],
		attributes,
		nil)

	_, err = l.Search(searchRequest)
	if err == nil {
		t.Fatal("Expected Error, got nil")
	}

	t.Log("TestMatchDNError:", err)
}
