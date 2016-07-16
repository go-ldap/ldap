package ldap_test

import (
	"bytes"
	"gopkg.in/ldap.v2"
	"testing"
)

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
	ex := bytes.NewBuffer([]byte(ldifRFC2849Example))
	l := &ldap.LDIF{}
	err := l.Parse(ex)
	if err != nil {
		t.Errorf("Failed to parse RFC 2849 example: %s", err)
	}
}

var ldifEmpty = `dn: uid=someone,dc=example,dc=org
cn:
cn: Some User
`

func TestLDIFParseEmptyAttr(t *testing.T) {
	ex := bytes.NewBuffer([]byte(ldifEmpty))
	l := &ldap.LDIF{}
	err := l.Parse(ex)
	if err == nil {
		t.Errorf("Did not fail to parse empty attribute")
	}
}

var ldifMissingDN = `objectclass: top
cn: Some User
`

func TestLDIFParseMissingDN(t *testing.T) {
	ex := bytes.NewBuffer([]byte(ldifMissingDN))
	l := &ldap.LDIF{}
	err := l.Parse(ex)
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
	ex := bytes.NewBuffer([]byte(ldifContinuation))
	l := &ldap.LDIF{}
	err := l.Parse(ex)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	e := l.Entries[0]
	if e.GetAttributeValues("sn")[0] != "Some One" {
		t.Errorf("Value of continuation line wrong")
	}
}

var ldifBase64 = `dn: uid=someone,dc=example,dc=org
sn:: U29tZSBPbmU=
`

func TestLDIFBase64(t *testing.T) {
	ex := bytes.NewBuffer([]byte(ldifBase64))
	l := &ldap.LDIF{}
	err := l.Parse(ex)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}

	e := l.Entries[0]
	val := e.GetAttributeValues("sn")[0]
	cmp := "Some One"
	if val != cmp {
		t.Errorf("Value of base64 value wrong: >%v< >%v<", []byte(val), []byte(cmp))
	}
}

var ldifTrailingBlank = `dn: uid=someone,dc=example,dc=org
sn:: U29tZSBPbmU=

`

func TestLDIFTrailingBlank(t *testing.T) {
	ex := bytes.NewBuffer([]byte(ldifTrailingBlank))
	l := &ldap.LDIF{}
	err := l.Parse(ex)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
}
