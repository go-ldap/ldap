package ldap

import (
	"context"
	"crypto/tls"
	"log"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
)

const (
	ldapServer  = "ldap://ldap.itd.umich.edu:389"
	ldapsServer = "ldaps://ldap.itd.umich.edu:636"
	baseDN      = "dc=umich,dc=edu"
)

var filter = []string{
	"(cn=cis-fac)",
	"(&(owner=*)(cn=cis-fac))",
	"(&(objectclass=rfc822mailgroup)(cn=*Computer*))",
	"(&(objectclass=rfc822mailgroup)(cn=*Mathematics*))",
}

var attributes = []string{
	"cn",
	"description",
}

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
	_, err = l.SearchWithPaging(searchRequest, 5)
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
	for _, testInfo := range []struct {
		src       string
		expecting string
	}{
		{
			src:       "a\x00b(c)d*e\\f",
			expecting: `a\00b\28c\29d\2ae\5cf`,
		},
		{
			src:       "Lučić",
			expecting: `Lu\c4\8di\c4\87`,
		},
		{
			src:       `\\some-server\code`,
			expecting: `\5c\5csome-server\5ccode`,
		},
		{
			src:       `Mi*함*r`,
			expecting: `Mi\2a\ed\95\a8\2ar`,
		},
	} {
		got := EscapeFilter(testInfo.src)
		if got != testInfo.expecting {
			t.Errorf("Got %s, expected %s", got, testInfo.expecting)
		}
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

func Test_addControlDescriptions(t *testing.T) {
	type args struct {
		packet *ber.Packet
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{name: "timeBeforeExpiration", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x29, 0x30, 0x27, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0xa, 0x30, 0x8, 0xa0, 0x6, 0x80, 0x4, 0x7f, 0xff, 0xf6, 0x5c})}, wantErr: false},
		{name: "graceAuthNsRemaining", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x26, 0x30, 0x24, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x7, 0x30, 0x5, 0xa0, 0x3, 0x81, 0x1, 0x11})}, wantErr: false},
		{name: "passwordExpired", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x0})}, wantErr: false},
		{name: "accountLocked", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x1})}, wantErr: false},
		{name: "passwordModNotAllowed", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x3})}, wantErr: false},
		{name: "mustSupplyOldPassword", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x4})}, wantErr: false},
		{name: "insufficientPasswordQuality", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x5})}, wantErr: false},
		{name: "passwordTooShort", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x6})}, wantErr: false},
		{name: "passwordTooYoung", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x7})}, wantErr: false},
		{name: "passwordInHistory", args: args{packet: ber.DecodePacket([]byte{0xa0, 0x24, 0x30, 0x22, 0x4, 0x19, 0x31, 0x2e, 0x33, 0x2e, 0x36, 0x2e, 0x31, 0x2e, 0x34, 0x2e, 0x31, 0x2e, 0x34, 0x32, 0x2e, 0x32, 0x2e, 0x32, 0x37, 0x2e, 0x38, 0x2e, 0x35, 0x2e, 0x31, 0x4, 0x5, 0x30, 0x3, 0x81, 0x1, 0x8})}, wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := addControlDescriptions(tt.args.packet); (err != nil) != tt.wantErr {
				t.Errorf("addControlDescriptions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEscapeDN(t *testing.T) {
	tests := []struct {
		name string
		dn   string
		want string
	}{
		{name: "emptyString", dn: "", want: ""},
		{name: "comma", dn: "test,user", want: "test\\,user"},
		{name: "numberSign", dn: "#test#user#", want: "\\#test#user#"},
		{name: "backslash", dn: "\\test\\user\\", want: "\\\\test\\\\user\\\\"},
		{name: "whitespaces", dn: "  test user  ", want: "\\  test user \\ "},
		{name: "nullByte", dn: "\u0000te\x00st\x00user" + string(rune(0)), want: "\\00te\\00st\\00user\\00"},
		{name: "variousCharacters", dn: "test\"+,;<>\\-_user", want: "test\\\"\\+\\,\\;\\<\\>\\\\-_user"},
		{name: "multiByteRunes", dn: "test\u0391user ", want: "test\u0391user\\ "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EscapeDN(tt.dn); got != tt.want {
				t.Errorf("EscapeDN(%s) = %s, expected %s", tt.dn, got, tt.want)
			}
		})
	}
}

func TestSearchAsync(t *testing.T) {
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	searchRequest := NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[2],
		attributes,
		nil)

	srs := make([]*Entry, 0)
	ctx := context.Background()
	r := l.SearchAsync(ctx, searchRequest, 64)
	for r.Next() {
		srs = append(srs, r.Entry())
	}
	if err := r.Err(); err != nil {
		log.Fatal(err)
	}

	t.Logf("TestSearcAsync: %s -> num of entries = %d", searchRequest.Filter, len(srs))
}

func TestSearchAsyncAndCancel(t *testing.T) {
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	searchRequest := NewSearchRequest(
		baseDN,
		ScopeWholeSubtree, DerefAlways, 0, 0, false,
		filter[2],
		attributes,
		nil)

	cancelNum := 10
	srs := make([]*Entry, 0)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := l.SearchAsync(ctx, searchRequest, 0)
	for r.Next() {
		srs = append(srs, r.Entry())
		if len(srs) == cancelNum {
			cancel()
		}
	}
	if err := r.Err(); err != nil {
		log.Fatal(err)
	}

	if len(srs) > cancelNum+3 {
		// the cancellation process is asynchronous,
		// so it might get some entries after calling cancel()
		t.Errorf("Got entries %d, expected < %d", len(srs), cancelNum+3)
	}
	t.Logf("TestSearchAsyncAndCancel: %s -> num of entries = %d", searchRequest.Filter, len(srs))
}
