package ldif_test

import (
	"gopkg.in/ldap.v2"
	"gopkg.in/ldap.v2/ldif"
	"testing"
)

var personLDIF = `dn: uid=someone,ou=people,dc=example,dc=org
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: someone
cn: Someone
mail: someone@example.org

`

var ouLDIF = `dn: ou=people,dc=example,dc=org
objectClass: top
objectClass: organizationalUnit
ou: people

`

var entries = []*ldap.Entry{
	{
		DN: "ou=people,dc=example,dc=org",
		Attributes: []*ldap.EntryAttribute{
			{
				Name: "objectClass",
				Values: []string{
					"top",
					"organizationalUnit",
				},
			},
			{
				Name:   "ou",
				Values: []string{"people"},
			},
		},
	},
	{
		DN: "uid=someone,ou=people,dc=example,dc=org",
		Attributes: []*ldap.EntryAttribute{
			{
				Name: "objectClass",
				Values: []string{
					"top",
					"person",
					"organizationalPerson",
					"inetOrgPerson",
				},
			},
			{
				Name:   "uid",
				Values: []string{"someone"},
			},
			{
				Name:   "cn",
				Values: []string{"Someone"},
			},
			{
				Name:   "mail",
				Values: []string{"someone@example.org"},
			},
		},
	},
}

func TestMarshalSingleEntry(t *testing.T) {
	res, err := ldif.Marshal(ldif.EntriesAsLDIF(entries[1]))
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != personLDIF {
		t.Errorf("unexpected result: >>%s<<\n", res)
	}
}

func TestMarshalEntries(t *testing.T) {
	res, err := ldif.Marshal(ldif.EntriesAsLDIF(entries...))
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != ouLDIF+personLDIF {
		t.Errorf("unexpected result: >>%s<<\n", res)
	}
}

func TestMarshalB64(t *testing.T) {
	entryLDIF := `dn: ou=people,dc=example,dc=org
objectClass: top
objectClass: organizationalUnit
ou: people
description:: VGhlIFBlw7ZwbGUgw5ZyZ2FuaXphdGlvbg==

`
	entry := &ldap.Entry{
		DN: "ou=people,dc=example,dc=org",
		Attributes: []*ldap.EntryAttribute{
			{
				Name: "objectClass",
				Values: []string{
					"top",
					"organizationalUnit",
				},
			},
			{
				Name:   "ou",
				Values: []string{"people"},
			},
			{
				Name:   "description",
				Values: []string{"The Peöple Örganization"},
			},
		},
	}
	res, err := ldif.Marshal(ldif.EntriesAsLDIF(entry))
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != entryLDIF {
		t.Errorf("unexpected result: >>%s<<\n", res)
	}
}

func TestMarshalMod(t *testing.T) {
	modLDIF := `dn: uid=someone,ou=people,dc=example,dc=org
changetype: modify
add: givenName
givenName: Some
-
delete: mail
-
delete: telephoneNumber
telephoneNumber: 123 456 789 - 0
-
replace: sn
sn: One
-

`
	mod := ldap.NewModifyRequest("uid=someone,ou=people,dc=example,dc=org")
	mod.Replace("sn", []string{"One"})
	mod.Add("givenName", []string{"Some"})
	mod.Delete("mail", []string{})
	mod.Delete("telephoneNumber", []string{"123 456 789 - 0"})
	l, err := ldif.ChangesAsLDIF(mod)
	if err != nil {
		t.Errorf("Failed to return changes as LDIF: %s", err)
	}
	res, err := ldif.Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != modLDIF {
		t.Errorf("unexpected result: >>%s<<", res)
	}
}

func TestMarshalAdd(t *testing.T) {
	addLDIF := `dn: uid=someone,ou=people,dc=example,dc=org
changetype: add
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: inetOrgPerson
uid: someone
cn: Someone
mail: someone@example.org

`
	add := ldap.NewAddRequest("uid=someone,ou=people,dc=example,dc=org")
	for _, a := range entries[1].Attributes {
		add.Attribute(a.Name, a.Values)
	}
	l, err := ldif.ChangesAsLDIF(add)
	if err != nil {
		t.Errorf("Failed to return changes as LDIF: %s", err)
	}
	res, err := ldif.Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != addLDIF {
		t.Errorf("unexpected result: >>%s<<", res)
	}
}

func TestMarshalDel(t *testing.T) {
	delLDIF := `dn: uid=someone,ou=people,dc=example,dc=org
changetype: delete

`
	del := ldap.NewDelRequest("uid=someone,ou=people,dc=example,dc=org", nil)
	l, err := ldif.ChangesAsLDIF(del)
	if err != nil {
		t.Errorf("Failed to return changes as LDIF: %s", err)
	}
	res, err := ldif.Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != delLDIF {
		t.Errorf("unexpected result: >>%s<<", res)
	}
}

// vim: ts=4 sw=4 noexpandtab nolist
