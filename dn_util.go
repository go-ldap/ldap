package ldap

import (
	enchex "encoding/hex"
	"errors"
	"strings"
)

// When true, uses strings.EqualFold to compare the values of an RDN.
// This is usually needed as true for most values, set to false when
// your DNs contain case sensitive values.
var RDNCompareFold bool = true

var ErrDNNotSubordinate = errors.New("Not a subordinate")

// Returns the stringified version of a *DN, the RDN values are escaped
func (dn *DN) String() string {
	var rdns []string
	for _, r := range dn.RDNs {
		var tv []string
		for _, av := range r.Attributes {
			tv = append(tv, strings.ToLower(av.Type)+"="+EscapeValue(av.Value))
		}
		rdns = append(rdns, strings.Join(tv, "+"))
	}
	return strings.Join(rdns, ",")
}

func EscapeValue(value string) (escaped string) {
	for _, r := range value {
		switch r {
		case ',', '+', '"', '\\', '<', '>', ';', '#', '=':
			escaped += "\\" + string(r)
		default:
			if uint(r) < 32 {
				escaped += "\\" + enchex.EncodeToString([]byte(string(r)))
			} else {
				escaped += string(r)
			}
		}
	}
	return
}

// check if all RDNs of both DNs are equal
func (dn *DN) Equal(other *DN) bool {
	if len(dn.RDNs) != len(other.RDNs) {
		return false
	}
	for i, rdn := range dn.RDNs {
		if !rdn.Equal(other.RDNs[i]) {
			return false
		}
	}
	return true
}

// Check if all types and values of both RDNs are equal, the result may be
// influenced by the value of RDNCompareFold.
func (r *RelativeDN) Equal(o *RelativeDN) bool {
	if len(r.Attributes) != len(o.Attributes) {
		return false
	}
	for i, av := range r.Attributes {
		if strings.ToLower(av.Type) != strings.ToLower(o.Attributes[i].Type) {
			return false
		}
		if RDNCompareFold {
			if !strings.EqualFold(av.Value, o.Attributes[i].Value) {
				return false
			}
		} else {
			if av.Value != o.Attributes[i].Value {
				return false
			}
		}
	}
	return true
}

// Returns true if the "other" DN is a parent of "dn"
func (dn *DN) IsSubordinate(other *DN) bool {
	if off := len(dn.RDNs) - len(other.RDNs); off <= 0 {
		return false
	} else {
		for i, rdn := range other.RDNs {
			if !rdn.Equal(dn.RDNs[i+off]) {
				return false
			}
		}
	}
	return true
}

// appends the "other" DN to the "dn", e.g.
//
//  dn, err := ldap.ParseDN("CN=Someone")
//  base, err := ldap.ParseDN("ou=people,dc=example,dc=org")
//  dn.Append(base) -> "cn=Someone,ou=people,dc=example,dc=org"
func (dn *DN) Append(other *DN) {
	dn.RDNs = append(dn.RDNs, other.RDNs...)
}

// removes the "other" DN from the "dn", e.g.
//
//  dn, err := ldap.ParseDN(""cn=Someone,ou=people,dc=example,dc=org")
//  base, err := ldap.ParseDN("ou=people,dc=example,dc=org")
//  dn.Strip(base) -> "cn=Someone"
//
// Note: the "other" DN must be a parent of the "dn"
func (dn *DN) Strip(base *DN) error {
	if !dn.IsSubordinate(base) {
		return ErrDNNotSubordinate
	}
	dn.RDNs = dn.RDNs[0 : len(dn.RDNs)-len(base.RDNs)]
	return nil
}

// Changes the first RDN of DN to the given one
func (dn *DN) Rename(rdn *RelativeDN) {
	dn.RDNs[0] = rdn
}

// Moves the first RDN to the new base
func (dn *DN) Move(newBase *DN) {
	dn.RDNs = dn.RDNs[:1]
	dn.Append(newBase)
}

// Returns the value of the first RDN, e.g.
//
//  dn, err := ldap.ParseDN("uid=someone,ou=people,dc=example,dc=org")
//  dn.RDN() -> "someone"
func (dn *DN) RDN() string {
	if len(dn.RDNs) == 0 || len(dn.RDNs[0].Attributes) == 0 {
		return ""
	}
	return dn.RDNs[0].Attributes[0].Value
}

// Returns the parent of the "dn" as a cloned *DN
func (dn *DN) Parent() *DN {
	c := dn.Clone()
	if len(c.RDNs) > 0 {
		c.RDNs = c.RDNs[1:]
		return c
	}
	c.RDNs = []*RelativeDN{}
	return c
}

// Returns a clone of the DN
func (dn *DN) Clone() *DN {
	c := &DN{}
	for _, r := range dn.RDNs {
		rc := &RelativeDN{}
		for _, tv := range r.Attributes {
			rc.Attributes = append(rc.Attributes, &AttributeTypeAndValue{Type: tv.Type, Value: tv.Value})
		}
		c.RDNs = append(c.RDNs, rc)
	}
	return c
}

// Sorting DNs:
//   all := []*ldap.DN{dn1, dn2, dn3, dn4}
//   sort.Sort(DNs(all))
//   for _, dn := range all {
//      println(dn.String())
//   }
//
// The result order from deepest part in tree upwards, so you could
// easily search for all dns in a base, sort them and then remove
// every DN in that order to remove the tree (including the search base)
type DNs []*DN

func (d DNs) Len() int {
	return len(([]*DN)(d))
}

func (d DNs) Swap(i, j int) {
	([]*DN)(d)[i], ([]*DN)(d)[j] = ([]*DN)(d)[j], ([]*DN)(d)[i]
}

func (d DNs) Less(i, j int) bool {
	if ([]*DN)(d)[i].IsSubordinate(([]*DN)(d)[j]) {
		return true
	}
	if ([]*DN)(d)[i].Parent().Equal(([]*DN)(d)[j].Parent()) {
		return ([]*DN)(d)[i].RDNs[0].Less(([]*DN)(d)[j].RDNs[0])
	}
	return false
}

func (r *RelativeDN) Less(o *RelativeDN) bool {
	if len(r.Attributes) != len(o.Attributes) {
		return len(r.Attributes) < len(o.Attributes)
	}
	for i, a := range r.Attributes {
		if strings.ToLower(a.Type) < strings.ToLower(o.Attributes[i].Type) {
			return true
		}
		if RDNCompareFold {
			if strings.ToLower(a.Value) < strings.ToLower(o.Attributes[i].Value) {
				return true
			}
		} else {
			if a.Value < o.Attributes[i].Value {
				return true
			}
		}
	}
	return false
}

// vim: ts=4 sw=4 noexpandtab
