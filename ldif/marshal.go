package ldif

import (
	"encoding/base64"
	"errors"
)

var foldWidth int = 76

var ErrMixed = errors.New("cannot mix change records and content records")

// Returns an LDIF string from the given LDIF struct. The default line lenght
// is 76 characters. This can be changed by setting FoldWidth on the LDIF struct.
func Marshal(l *LDIF) (data string, err error) {
	data = "version: 1\n"
	hasEntry := false
	hasChange := false
	fw: = foldWidth
	if l.FoldWidth != 0 {
		fw = l.FoldWidth
	}

	for _, e := range l.Entries {
		switch {
		case e.Add != nil:
			hasChange = true
			if hasEntry {
				return "", ErrMixed
			}
			return "", errors.New("changetype 'add' not supported")
			/*
				data += foldLine("dn: " + e.Add.DN, fw) + "\n"
				data += "changetype: add\n"
				for _, add := range e.Add.Attributes {
					if len(add.AttrVals) == 0 {
						return "", errors.New("changetype 'add' requires non empty value list")
					}
					for _, v := range add.AttrVals {
						ev, t := encodeValue(v)
						col := ": "
						if t {
							col = ":: "
						}
						data += foldLine(add.AttrType+col+ev, fw) + "\n"
					}
					data += "-\n"
				}
			*/
		case e.Del != nil:
			hasChange = true
			if hasEntry {
				return "", ErrMixed
			}
			return "", errors.New("changetype 'delete' not supported")
			/*
				data += foldLine("dn: " + e.Del.DN, fw) + "\n"
				data += "changetype: delete\n-\n"
			*/
		case e.Modify != nil:
			hasChange = true
			if hasEntry {
				return "", ErrMixed
			}
			return "", errors.New("changetype 'modify' not supported")
			/*
				data += foldLine("dn: " + e.Modify.DN, fw) + "\n"
				data += "changetype: modify\n"
				for _, mod := range e.Modify.AddAttributes {
					if len(mod.AttrVals) == 0 {
						return "", errors.New("changetype 'modify', op 'add' requires non empty value list")
					}

					data += "add: " + mod.AttrType + "\n"
					for _, v := range mod.AttrVals {
						ev, t := encodeValue(v)
						col := ": "
						if t {
							col = ":: "
						}
						data += foldLine(mod.AttrType+col+ev, fw) + "\n"
					}
					data += "-\n"
				}
				for _, mod := range e.Modify.DeleteAttributes {
					data += "delete: " + mod.AttrType + "\n"
					for _, v := range mod.AttrVals {
						ev, t := encodeValue(v)
						col := ": "
						if t {
							col = ":: "
						}
						data += foldLine(mod.AttrType+col+ev, fw) + "\n"
					}
					data += "-\n"
				}
				for _, mod := range e.Modify.ReplaceAttributes {
					if len(mod.AttrVals) == 0 {
						return "", errors.New("changetype 'modify', op 'replace' requires non empty value list")
					}
					data += "replace: " + mod.AttrType + "\n"
					for _, v := range mod.AttrVals {
						ev, t := encodeValue(v)
						col := ": "
						if t {
							col = ":: "
						}
						data += foldLine(mod.AttrType+col+ev, fw) + "\n"
					}
					data += "-\n"
				}
			*/
		default:
			hasEntry = true
			if hasChange {
				return "", ErrMixed
			}
			data += foldLine("dn: " + e.Entry.DN, fw) + "\n"
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
			data += "\n"
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

// vim: ts=4 sw=4 noexpandtab nolist
