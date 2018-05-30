package ldap

import (
	"log"
	"reflect"
	"testing"
	"time"
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
			t.Fatalf("subsequent calls to NewEntry did not yield the same result:\n\texpected:\n\t%s\n\tgot:\n\t%s\n", executedEntry, testEntry)
		}
		iteration = iteration + 1
	}
}

func ExampleDirSync() {
	conn, err := Dial("tcp", "ad.example.org:389")
	if err != nil {
		log.Fatalf("Failed to connect: %s\n", err)
	}
	defer conn.Close()

	_, err = conn.SimpleBind(&SimpleBindRequest{
		Username: "cn=Some User,ou=people,dc=example,dc=org",
		Password: "MySecretPass",
	})

	req := &SearchRequest{
		BaseDN:     `DC=example,DC=org`,
		Filter:     `(&(objectClass=person)(!(objectClass=computer)))`,
		Attributes: []string{"*"},
		Scope:      ScopeWholeSubtree,
	}
	doMore := true
	for doMore {
		res, err := conn.DirSync(req, DirSyncObjectSecurity, 1000)
		if err != nil {
			log.Fatalf("failed to search: %s", err)
		}
		for _, entry := range res.Entries {
			entry.Print()
		}
		ctrl := FindControl(res.Controls, ControlTypeDirSync)
		if ctrl == nil || ctrl.(*ControlDirSync).Flags == 0 {
			doMore = false
		}
	}
	for {
		res, err := conn.DirSync(req, DirSyncObjectSecurity, 1000)
		if err != nil {
			log.Fatalf("failed to search: %s", err)
		}
		for _, entry := range res.Entries {
			entry.Print()
		}
		time.Sleep(15 * time.Second)
	}

}
