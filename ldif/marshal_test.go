package ldif_test

import (
	"bytes"
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
	l := &ldif.LDIF{
		Entries: []*ldif.Entry{
			{Entry: entries[1]},
		},
	}
	res, err := ldif.Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != personLDIF {
		t.Errorf("unexpected result: >>%s<<\n", res)
	}
}

func TestMarshalEntries(t *testing.T) {
	l := &ldif.LDIF{
		Entries: []*ldif.Entry{
			{Entry: entries[0]},
			{Entry: entries[1]},
		},
	}
	res, err := ldif.Marshal(l)
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
	l := &ldif.LDIF{
		Entries: []*ldif.Entry{
			{Entry: entry},
		},
	}
	res, err := ldif.Marshal(l)
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
	l := &ldif.LDIF{
		Entries: []*ldif.Entry{
			{Modify: mod},
		},
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
	l := &ldif.LDIF{
		Entries: []*ldif.Entry{
			{Add: add},
		},
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
	l := &ldif.LDIF{
		Entries: []*ldif.Entry{
			{Del: del},
		},
	}
	res, err := ldif.Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal entry: %s", err)
	}
	if res != delLDIF {
		t.Errorf("unexpected result: >>%s<<", res)
	}
}

func TestDump(t *testing.T) {
	delLDIF := `dn: uid=someone,ou=people,dc=example,dc=org
changetype: delete

`
	del := ldap.NewDelRequest("uid=someone,ou=people,dc=example,dc=org", nil)
	buf := bytes.NewBuffer(nil)
	err := ldif.Dump(buf, 0, del)
	if err != nil {
		t.Errorf("Failed to dump entry: %s", err)
	}
	res := buf.String()
	if res != delLDIF {
		t.Errorf("unexpected result: >>%s<<", res)
	}
}

/*
func TestMarshalModDN(t *testing.T) {
	moddnLDIF := `dn: uid=someone,ou=people,dc=example,dc=org
changetype: moddn
deleteoldrdn: 1
newrdn: uid=somebody
newsuperior: ou=people,dc=example,dc=org
-

`
	mod := ldap.NewModifyDNRequest("uid=someone,ou=people,dc=example,dc=org", "uid=somebody", true, "ou=people,dc=example,dc=org")
    l := &ldif.LDIF{
        Entries: []*ldif.Entry{
            {ModifyDN: mod},
        },
    }
	res, err := ldif.Marshal(l)
	if err != nil {
		t.Errorf("Failed to marshal: %s", err)
	}
	if res != moddnLDIF {
		t.Errorf("unexprected result: >>%s<<", res)
	}
}
*/
