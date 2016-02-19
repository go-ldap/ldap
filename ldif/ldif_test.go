package ldif_test

import (
	"bytes"
	"gopkg.in/ldap.v2/ldif"
	"io/ioutil"
	"os"
	"testing"
)

func parseString(str string) (*ldif.LDIF, error) {
	ex := bytes.NewBuffer([]byte(str))
	l := &ldif.LDIF{}
	err := ldif.Unmarshal(ex, l)
	return l, err
}

var ldifRFC2849Example = `version: 1
dn: cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Barbara Jensen
cn: Barbara J Jensen
cn: Babs Jensen
sn: Jensen
uid: bjensen
telephonenumber: +1 408 555 1212
description: A big sailing fan.

dn: cn=Bjorn Jensen, ou=Accounting, dc=airius, dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Bjorn Jensen
sn: Jensen
telephonenumber: +1 408 555 1212
`

func TestLDIFParseRFC2849Example(t *testing.T) {
	l, err := parseString(ldifRFC2849Example)
	if err != nil {
		t.Errorf("Failed to parse RFC 2849 example: %s", err)
	}
	if l.Entries[1].Entry.GetAttributeValues("sn")[0] != "Jensen" {
		t.Errorf("RFC 2849 example: empty 'sn' in second entry")
	}
}

var ldifEmpty = `dn: uid=someone,dc=example,dc=org
cn:
cn: Some User
`

func TestLDIFParseEmptyAttr(t *testing.T) {
	_, err := parseString(ldifEmpty)
	if err == nil {
		t.Errorf("Did not fail to parse empty attribute")
	}
}

var ldifMissingDN = `objectclass: top
cn: Some User
`

func TestLDIFParseMissingDN(t *testing.T) {
	_, err := parseString(ldifMissingDN)
	if err == nil {
		t.Errorf("Did not fail to parse missing DN attribute")
	}
}

var ldifContinuation = `dn: uid=someone,dc=example,dc=org
sn: Some
  One
cn: Someone
`

func TestLDIFContinuation(t *testing.T) {
	l, err := parseString(ldifContinuation)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	e := l.Entries[0]
	if e.Entry.GetAttributeValues("sn")[0] != "Some One" {
		t.Errorf("Value of continuation line wrong")
	}
}

var ldifBase64 = `dn: uid=someone,dc=example,dc=org
sn:: U29tZSBPbmU=
`

func TestLDIFBase64(t *testing.T) {
	l, err := parseString(ldifBase64)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}

	e := l.Entries[0]
	val := e.Entry.GetAttributeValues("sn")[0]
	cmp := "Some One"
	if val != cmp {
		t.Errorf("Value of base64 value wrong: >%v< >%v<", []byte(val), []byte(cmp))
	}
}

var ldifBase64Broken = `dn: uid=someone,dc=example,dc=org
sn:: XXX-U29tZSBPbmU=
`

func TestLDIFBase64Broken(t *testing.T) {
	_, err := parseString(ldifBase64Broken)
	if err == nil {
		t.Errorf("Did not failed to parse broken base64", err)
	}
}

var ldifTrailingBlank = `dn: uid=someone,dc=example,dc=org
sn:: U29tZSBPbmU=

`

func TestLDIFTrailingBlank(t *testing.T) {
	_, err := parseString(ldifTrailingBlank)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
}

var ldifComments = `dn: uid=someone,dc=example,dc=org
# a comment
 continued comment
sn: someone
`

func TestLDIFComments(t *testing.T) {
	l, err := parseString(ldifComments)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	if l.Entries[0].Entry.GetAttributeValues("sn")[0] != "someone" {
		t.Errorf("No sn attribute")
	}
}

var ldifNoSpace = `dn:uid=someone,dc=example,dc=org
sn:someone
`

func TestLDIFNoSpace(t *testing.T) {
	l, err := parseString(ldifNoSpace)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	if l.Entries[0].Entry.GetAttributeValues("sn")[0] != "someone" {
		t.Errorf("No/wrong sn attribute: '%s'", l.Entries[0].Entry.GetAttributeValues("sn")[0])
	}
}

var ldifMultiSpace = `dn:  uid=someone,dc=example,dc=org
sn:    someone
`

func TestLDIFMultiSpace(t *testing.T) {
	l, err := parseString(ldifMultiSpace)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	if l.Entries[0].Entry.GetAttributeValues("sn")[0] != "someone" {
		t.Errorf("No/wrong sn attribute: '%s'", l.Entries[0].Entry.GetAttributeValues("sn")[0])
	}
}

func TestLDIFURL(t *testing.T) {
	f, err := ioutil.TempFile("", "ldifurl")
	if err != nil {
		t.Errorf("Failed to create temp file: %s", err)
	}
	defer os.Remove(f.Name())
	f.Write([]byte("TEST\n"))
	f.Sync()
	l, err := parseString("dn: uid=someone,dc=example,dc=org\ndescription:< file://" + f.Name() + "\n")
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	if l.Entries[0].Entry.GetAttributeValues("description")[0] != "TEST\n" {
		t.Errorf("wrong file?")
	}
}

// vim: ts=4 sw=4 noexpandtab nolist
