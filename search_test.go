package ldap

import (
	"reflect"
	"testing"

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
			},
		}

		type User struct {
			Dn     string `ldap:"dn"`
			Cn     string `ldap:"cn"`
			Mail   string `ldap:"mail"`
			ID     int    `ldap:"id"`
			LongID int64  `ldap:"longId"`
			Data   []byte `ldap:"data"`
		}

		expect := &User{
			Dn:     "cn=mario,ou=Users,dc=go-ldap,dc=github,dc=com",
			Cn:     "mario",
			Mail:   "mario@go-ldap.com",
			ID:     2147483647,
			LongID: 9223372036854775807,
			Data:   []byte("data"),
		}
		result := &User{}
		err := entry.Unmarshal(result)

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
