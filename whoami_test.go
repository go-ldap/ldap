package ldap_test

import (
	"fmt"
	"gopkg.in/ldap.v2"
)

func ExampleWhoAmI() {
	conn, err := ldap.Dial("tcp", "ldap.example.org:389")
	if err != nil {
		fmt.Errorf("Failed to connect: %s\n", err)
	}

	_, err = conn.SimpleBind(&ldap.SimpleBindRequest{
		Username: "uid=someone,ou=people,dc=example,dc=org",
		Password: "MySecretPass",
	})
	if err != nil {
		fmt.Errorf("Failed to bind: %s\n", err)
	}

	res, err := conn.WhoAmI(nil)
	if err != nil {
		fmt.Errorf("Failed to call WhoAmI(): %s\n", err)
	}
	fmt.Printf("%s\n", res.AuthzId)
}
