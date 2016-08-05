package ldif_test

import (
	"io/ioutil"
	"os"
	"testing"

	"gopkg.in/ldap.v2/ldif"
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
	l, err := ldif.Parse(ldifRFC2849Example)
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
	_, err := ldif.Parse(ldifEmpty)
	if err == nil {
		t.Errorf("Did not fail to parse empty attribute")
	}
}

var ldifMissingDN = `objectclass: top
cn: Some User
`

func TestLDIFParseMissingDN(t *testing.T) {
	_, err := ldif.Parse(ldifMissingDN)
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
	l, err := ldif.Parse(ldifContinuation)
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
	l, err := ldif.Parse(ldifBase64)
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
	_, err := ldif.Parse(ldifBase64Broken)
	if err == nil {
		t.Errorf("Did not failed to parse broken base64")
	}
}

var ldifTrailingBlank = `dn: uid=someone,dc=example,dc=org
sn:: U29tZSBPbmU=

`

func TestLDIFTrailingBlank(t *testing.T) {
	_, err := ldif.Parse(ldifTrailingBlank)
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
	l, err := ldif.Parse(ldifComments)
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
	l, err := ldif.Parse(ldifNoSpace)
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
	l, err := ldif.Parse(ldifMultiSpace)
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
	l, err := ldif.Parse("dn: uid=someone,dc=example,dc=org\ndescription:< file://" + f.Name() + "\n")
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	if l.Entries[0].Entry.GetAttributeValues("description")[0] != "TEST\n" {
		t.Errorf("wrong file?")
	}
}

var ldifMultiBlankLines = `# Organization Units
dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
objectClass: top
ou: users


# searches for above empty line for dn but fails and errors out in this PR
# Even though this is a valid LDIF file for ldapadd
dn: ou=groups,dc=example,dc=com
objectClass: organizationalUnit
objectClass: top
ou: groups
`

func TestLDIFMultiBlankLines(t *testing.T) {
	l, err := ldif.Parse(ldifMultiBlankLines)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	ou := l.Entries[1].Entry.GetAttributeValue("ou")
	if ou != "groups" {
		t.Errorf("wrong ou in second entry: %s", ou)
	}
}

var ldifLeadingTrailingBlankLines = `

# Organization Units
dn: ou=users,dc=example,dc=com
objectClass: organizationalUnit
objectClass: top
ou: users


`

func TestLDIFLeadingTrailingBlankLines(t *testing.T) {
	l, err := ldif.Parse(ldifLeadingTrailingBlankLines)
	if err != nil {
		t.Errorf("Failed to parse LDIF: %s", err)
	}
	ou := l.Entries[0].Entry.GetAttributeValue("ou")
	if ou != "users" {
		t.Errorf("wrong ou in entry: %s", ou)
	}
}

var ldifVersionOnSecond = `dn: cn=Barbara Jensen, ou=Product Development, dc=airius, dc=com
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

version: 1
dn: cn=Bjorn Jensen, ou=Accounting, dc=airius, dc=com
objectclass: top
objectclass: person
objectclass: organizationalPerson
cn: Bjorn Jensen
sn: Jensen
telephonenumber: +1 408 555 1212
`

func TestLDIFVersionOnSecond(t *testing.T) {
	if _, err := ldif.Parse(ldifVersionOnSecond); err == nil {
		t.Errorf("did not fail to parse LDIF")
	}
}
