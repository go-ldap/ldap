package ldif

import (
	"encoding/base64"
	"errors"
	"fmt"
	"gopkg.in/ldap.v2"
)

var foldWidth = 76

// ErrMixed is the error, that we cannot mix change records and content
// records in one LDIF
var ErrMixed = errors.New("cannot mix change records and content records")

// Marshal returns an LDIF string from the given LDIF struct. The default
// line lenght is 76 characters. This can be changed by setting FoldWidth
// on the LDIF struct.
// For a FoldWidth < 0, no folding will be done, with 0, the default is used.
func Marshal(l *LDIF) (data string, err error) {
	if l.Version > 0 {
		data = "version: 1\n"
	}
	hasEntry := false
	hasChange := false
	fw := l.FoldWidth
	if fw == 0 {
		fw = foldWidth
	}

	for _, e := range l.Entries {
		switch {
		case e.Add != nil:
			hasChange = true
			if hasEntry {
				return "", ErrMixed
			}
			data += foldLine("dn: "+e.Add.DN, fw) + "\n"
			data += "changetype: add\n"
			for _, add := range e.Add.Attributes {
				if len(add.Vals) == 0 {
					return "", errors.New("changetype 'add' requires non empty value list")
				}
				for _, v := range add.Vals {
					ev, t := encodeValue(v)
					col := ": "
					if t {
						col = ":: "
					}
					data += foldLine(add.Type+col+ev, fw) + "\n"
				}
			}

		case e.Del != nil:
			hasChange = true
			if hasEntry {
				return "", ErrMixed
			}
			data += foldLine("dn: "+e.Del.DN, fw) + "\n"
			data += "changetype: delete\n"

		case e.Modify != nil:
			hasChange = true
			if hasEntry {
				return "", ErrMixed
			}
			data += foldLine("dn: "+e.Modify.DN, fw) + "\n"
			data += "changetype: modify\n"
			for _, mod := range e.Modify.AddAttributes {
				if len(mod.Vals) == 0 {
					return "", errors.New("changetype 'modify', op 'add' requires non empty value list")
				}

				data += "add: " + mod.Type + "\n"
				for _, v := range mod.Vals {
					ev, t := encodeValue(v)
					col := ": "
					if t {
						col = ":: "
					}
					data += foldLine(mod.Type+col+ev, fw) + "\n"
				}
				data += "-\n"
			}
			for _, mod := range e.Modify.DeleteAttributes {
				data += "delete: " + mod.Type + "\n"
				for _, v := range mod.Vals {
					ev, t := encodeValue(v)
					col := ": "
					if t {
						col = ":: "
					}
					data += foldLine(mod.Type+col+ev, fw) + "\n"
				}
				data += "-\n"
			}
			for _, mod := range e.Modify.ReplaceAttributes {
				if len(mod.Vals) == 0 {
					return "", errors.New("changetype 'modify', op 'replace' requires non empty value list")
				}
				data += "replace: " + mod.Type + "\n"
				for _, v := range mod.Vals {
					ev, t := encodeValue(v)
					col := ": "
					if t {
						col = ":: "
					}
					data += foldLine(mod.Type+col+ev, fw) + "\n"
				}
				data += "-\n"
			}

		default:
			hasEntry = true
			if hasChange {
				return "", ErrMixed
			}
			data += foldLine("dn: "+e.Entry.DN, fw) + "\n"
			for _, av := range e.Entry.Attributes {
				for _, v := range av.Values {
					ev, t := encodeValue(v)
					col := ": "
					if t {
						col = ":: "
					}
					data += foldLine(av.Name+col+ev, fw) + "\n"
				}
			}
		}
		data += "\n"
	}
	return data, nil
}

func encodeValue(value string) (string, bool) {
	required := false
	for _, r := range value {
		if r < ' ' || r > '~' { // ~ = 0x7E, <DEL> = 0x7F
			required = true
			break
		}
	}
	if !required {
		return value, false
	}
	return base64.StdEncoding.EncodeToString([]byte(value)), true
}

func foldLine(line string, fw int) (folded string) {
	if fw < 0 {
		return line
	}
	if len(line) <= fw {
		return line
	}

	folded = line[:fw] + "\n"
	line = line[fw:]

	for len(line) > fw-1 {
		folded += " " + line[:fw-1] + "\n"
		line = line[fw-1:]
	}

	if len(line) > 0 {
		folded += " " + line
	}
	return
}

// EntriesAsLDIF returns an LDIF struct with all entries, suitable to feed
// to Marshal(), e.g.:
//
//   res, err := conn.Search(&ldap.SearchRequest{BaseDN: b, Filter: f})
//   if err == nil {
//       resLDIF, err := ldif.Marshal(ldif.EntriesAsLDIF(res.Entries...))
//       if err == nil {
//          log.Printf("Result from search:\n\n%s\n", resLDIF)
//       }
//   }
func EntriesAsLDIF(entries ...*ldap.Entry) *LDIF {
	l := &LDIF{}
	for _, e := range entries {
		l.Entries = append(l.Entries, &Entry{Entry: e})
	}
	return l
}

// ChangesAsLDIF returns an LDIF struct with all changes (e.g.
// *ldap.AddRequest, *ldap.DelRequest, ...) suitable to feed to Marshal()
func ChangesAsLDIF(changes ...interface{}) (*LDIF, error) {
	l := &LDIF{}
	for _, c := range changes {
		var e *Entry
		switch c.(type) {
		case *ldap.AddRequest:
			e = &Entry{Add: c.(*ldap.AddRequest)}
		case *ldap.DelRequest:
			e = &Entry{Del: c.(*ldap.DelRequest)}
		case *ldap.ModifyRequest:
			e = &Entry{Modify: c.(*ldap.ModifyRequest)}
		// case *ldap.ModifyDNRequest:
		// 	e = &Entry{ModDN: c.(*ldap.ModifyDNRequest)}
		default:
			return nil, fmt.Errorf("unsupported type %T", c)
		}
		l.Entries = append(l.Entries, e)
	}
	return l, nil
}
