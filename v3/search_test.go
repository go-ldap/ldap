package ldap

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestNewEntry tests that repeated calls to NewEntry return the same value with the same input
func TestNewEntry(t *testing.T) {
	dn := "testDN"
	attributes := map[string][]string{
		"alpha":   {"value"},
		"beta":    {"value"},
		"gamma":   {"value"},
		"delta":   {"value"},
		"epsilon": {"value"},
	}
	executedEntry := NewEntry(dn, attributes)

	iteration := 0
	for {
		if iteration == 100 {
			break
		}
		testEntry := NewEntry(dn, attributes)
		if !reflect.DeepEqual(executedEntry, testEntry) {
			t.Fatalf("subsequent calls to NewEntry did not yield the same result:\n\texpected:\n\t%v\n\tgot:\n\t%v\n", executedEntry, testEntry)
		}
		iteration = iteration + 1
	}
}

func TestGetAttributeValue(t *testing.T) {
	dn := "testDN"
	attributes := map[string][]string{
		"Alpha":   {"value"},
		"bEta":    {"value"},
		"gaMma":   {"value"},
		"delTa":   {"value"},
		"epsiLon": {"value"},
	}
	entry := NewEntry(dn, attributes)
	if entry.GetAttributeValue("Alpha") != "value" {
		t.Errorf("failed to get attribute in original case")
	}

	if entry.GetEqualFoldAttributeValue("alpha") != "value" {
		t.Errorf("failed to get attribute in changed case")
	}
}

func TestEntry_Unmarshal(t *testing.T) {
	t.Run("passing a struct should fail", func(t *testing.T) {
		entry := &Entry{}

		type toStruct struct{}

		result := toStruct{}
		err := entry.Unmarshal(result)

		assert.NotNil(t, err)
	})

	t.Run("passing a ptr to string should fail", func(t *testing.T) {
		entry := &Entry{}

		str := "foo"
		err := entry.Unmarshal(&str)

		assert.NotNil(t, err)
	})

	t.Run("user struct be decoded", func(t *testing.T) {
		entry := &Entry{
			DN: "cn=mario,ou=Users,dc=go-ldap,dc=github,dc=com",
			Attributes: []*EntryAttribute{
				{
					Name:       "cn",
					Values:     []string{"mario"},
					ByteValues: nil,
				},
				{
					Name:       "mail",
					Values:     []string{"mario@go-ldap.com"},
					ByteValues: nil,
				},
				{
					Name:       "upn",
					Values:     []string{"mario@go-ldap.com.domain"},
					ByteValues: nil,
				},
				// Tests int value.
				{
					Name:       "id",
					Values:     []string{"2147483647"},
					ByteValues: nil,
				},
				// Tests int64 value.
				{
					Name:       "longId",
					Values:     []string{"9223372036854775807"},
					ByteValues: nil,
				},
				// Tests []byte value.
				{
					Name:   "data",
					Values: []string{"data"},
					ByteValues: [][]byte{
						[]byte("data"),
					},
				},
				// Tests time.Time value.
				{
					Name:       "createdTimestamp",
					Values:     []string{"202305041930Z"},
					ByteValues: nil,
				},
				// Tests *DN value
				{
					Name:       "owner",
					Values:     []string{"uid=foo,dc=example,dc=org"},
					ByteValues: nil,
				},
				// Tests []*DN value
				{
					Name:       "children",
					Values:     []string{"uid=bar,dc=example,dc=org", "uid=baz,dc=example,dc=org"},
					ByteValues: nil,
				},
			},
		}

		type User struct {
			Dn       string    `ldap:"dn"`
			Cn       string    `ldap:"cn"`
			Mail     string    `ldap:"mail"`
			UPN      *string   `ldap:"upn"`
			ID       int       `ldap:"id"`
			LongID   int64     `ldap:"longId"`
			Data     []byte    `ldap:"data"`
			Created  time.Time `ldap:"createdTimestamp"`
			Owner    *DN       `ldap:"owner"`
			Children []*DN     `ldap:"children"`
		}

		created, err := time.Parse("200601021504Z", "202305041930Z")
		if err != nil {
			t.Errorf("failed to parse ref time: %s", err)
		}
		owner, err := ParseDN("uid=foo,dc=example,dc=org")
		if err != nil {
			t.Errorf("failed to parse ref DN: %s", err)
		}
		var children []*DN
		for _, child := range []string{"uid=bar,dc=example,dc=org", "uid=baz,dc=example,dc=org"} {
			dn, err := ParseDN(child)
			if err != nil {
				t.Errorf("failed to parse child ref DN: %s", err)
			}
			children = append(children, dn)
		}

		UPN := "mario@go-ldap.com.domain"
		expect := &User{
			Dn:       "cn=mario,ou=Users,dc=go-ldap,dc=github,dc=com",
			Cn:       "mario",
			Mail:     "mario@go-ldap.com",
			UPN:      &UPN,
			ID:       2147483647,
			LongID:   9223372036854775807,
			Data:     []byte("data"),
			Created:  created,
			Owner:    owner,
			Children: children,
		}
		result := &User{}
		err = entry.Unmarshal(result)

		assert.Nil(t, err)
		assert.Equal(t, expect, result)
	})

	t.Run("group struct be decoded", func(t *testing.T) {
		entry := &Entry{
			DN: "cn=DREAM_TEAM,ou=Groups,dc=go-ldap,dc=github,dc=com",
			Attributes: []*EntryAttribute{
				{
					Name:       "cn",
					Values:     []string{"DREAM_TEAM"},
					ByteValues: nil,
				},
				{
					Name:       "member",
					Values:     []string{"mario", "luigi", "browser"},
					ByteValues: nil,
				},
			},
		}

		type Group struct {
			DN      string   `ldap:"dn" yaml:"dn" json:"dn"`
			CN      string   `ldap:"cn" yaml:"cn" json:"cn"`
			Members []string `ldap:"member"`
		}

		expect := &Group{
			DN:      "cn=DREAM_TEAM,ou=Groups,dc=go-ldap,dc=github,dc=com",
			CN:      "DREAM_TEAM",
			Members: []string{"mario", "luigi", "browser"},
		}

		result := &Group{}
		err := entry.Unmarshal(result)

		assert.Nil(t, err)
		assert.Equal(t, expect, result)
	})
}

func TestEntry_UnmarshalFunc(t *testing.T) {
	conn, err := DialURL(ldapServer)
	if err != nil {
		t.Fatalf("Failed to connect: %s\n", err)
	}
	defer conn.Close()

	searchResult, err := conn.Search(&SearchRequest{
		BaseDN:     baseDN,
		Scope:      ScopeWholeSubtree,
		Filter:     "(cn=cis-fac)",
		Attributes: []string{"cn", "objectClass"},
	})
	if err != nil {
		t.Fatalf("Failed to search: %s\n", err)
	}

	type user struct {
		ObjectClass string `custom_tag:"objectClass"`
		CN          string `custom_tag:"cn"`
	}

	t.Run("expect custom unmarshal function to be successfull", func(t *testing.T) {
		for _, entry := range searchResult.Entries {
			var u user
			if err := entry.UnmarshalFunc(&u, func(entry *Entry, fieldType reflect.StructField, fieldValue reflect.Value) error {
				tagData, ok := fieldType.Tag.Lookup("custom_tag")
				if !ok {
					return nil
				}

				value := entry.GetAttributeValue(tagData)
				// log.Printf("Marshaling field %s with tag %s and value '%s'", fieldType.Name, tagData, value)
				fieldValue.SetString(value)
				return nil
			}); err != nil {
				t.Errorf("Failed to unmarshal entry: %s\n", err)
			}

			if u.CN != entry.GetAttributeValue("cn") {
				t.Errorf("UnmarshalFunc did not set the field correctly. Expected: %s, got: %s", entry.GetAttributeValue("cn"), u.CN)
			}
		}
	})

	t.Run("expect an error within the custom unmarshal function", func(t *testing.T) {
		for _, entry := range searchResult.Entries {
			var u user
			err := entry.UnmarshalFunc(&u, func(entry *Entry, fieldType reflect.StructField, fieldValue reflect.Value) error {
				return fmt.Errorf("error from custom unmarshal func on field: %s", fieldType.Name)
			})
			if err == nil {
				t.Errorf("UnmarshalFunc should have returned an error")
			}
		}
	})
}
