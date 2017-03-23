package ldap_test

import (
	"fmt"
	"gopkg.in/ldap.v2"
	"sort"
	"testing"
)

func TestDNString(t *testing.T) {
	fmt.Printf("DNString: starting...\n")
	dn, _ := ldap.ParseDN("OU=Sales+CN=J. Smith,DC=example,DC=net")
	strdn := dn.String()
	if strdn != "ou=Sales+cn=J. Smith,dc=example,dc=net" {
		t.Errorf("Failed to stringify: %v\n", strdn)
	}
	fmt.Printf("DNString: -> %v\n", strdn)
	dn2, _ := ldap.ParseDN("CN=Lučić\\+Ma\\=><foo")
	if _, err := ldap.ParseDN(dn2.String()); err != nil {
		t.Errorf("Failed to parse stringified DN: %s", err)
	}
}

func TestDNParent(t *testing.T) {
	fmt.Printf("DN Parent: starting...\n")
	dn, _ := ldap.ParseDN("OU=Sales+CN=J. Smith,DC=example,DC=net")
	parent := dn.Parent()
	if dn.String() != "ou=Sales+cn=J. Smith,dc=example,dc=net" {
		t.Errorf("original dn modified -> %s\n", dn)
	}
	if parent.String() != "dc=example,dc=net" {
		t.Errorf("wrong parent -> %s\n", parent)
	}
	fmt.Printf("DN Parent: %s -> %s\n", dn, parent)
}

func TestDNMove(t *testing.T) {
	fmt.Printf("DN Rename and Move: starting...\n")
	dn, _ := ldap.ParseDN("OU=Sales+CN=J. Smith,DC=example,DC=net")
	base, _ := ldap.ParseDN("OU=People,DC=example,DC=net")
	rdn, _ := ldap.ParseDN("cn=J. Smith")
	dn.Move(base)
	if dn.String() != "ou=Sales+cn=J. Smith,ou=People,dc=example,dc=net" {
		t.Errorf("Failed to move: %s\n", dn)
	}
	dn.Rename(rdn.RDNs[0])
	if dn.String() != "cn=J. Smith,ou=People,dc=example,dc=net" {
		t.Errorf("Failed to rename: %s\n", dn)
	}
	fmt.Printf("DN Rename and Move: %s\n", dn)
}

func TestDNEqual(t *testing.T) {
	dn1, _ := ldap.ParseDN("OU=people,DC=example,DC=org")
	dn2, _ := ldap.ParseDN("ou=People,dc=Example,dc=ORG")
	ldap.RDNCompareFold = true
	if !dn1.Equal(dn2) {
		t.Errorf("both dns not equal")
	}
	ldap.RDNCompareFold = false
	if dn1.Equal(dn2) {
		t.Errorf("both dns equal with ldap.RDNCompareFold = false")
	}
	ldap.RDNCompareFold = true
}

func TestDNSort(t *testing.T) {
	var dns []*ldap.DN
	dnStrings := []string{
		"ou=people,dc=example,dc=org",
		"uid=another,ou=people,dc=example,dc=org",
		"uid=another+cn=one,ou=people,dc=example,dc=org",
		"dc=example,dc=org",
		"uid=someone,ou=people,dc=example,dc=org",
		"ou=robots,dc=example,dc=org",
		"uid=someone,ou=robots,dc=example,dc=org",
	}

	for _, s := range dnStrings {
		dn, _ := ldap.ParseDN(s)
		dns = append(dns, dn)
	}
	sort.Sort(ldap.DNs(dns))
	for _, dn := range dns {
		fmt.Printf("DN: %s\n", dn.String())
	}
	if dns[len(dns)-1].String() != "dc=example,dc=org" {
		t.Errorf("DN dc=example,dc=org is not last")
	}
	if dns[0].String() != "uid=another,ou=people,dc=example,dc=org" {
		t.Errorf("DN uid=another,ou=people,dc=example,dc=org is not first")
	}
}
