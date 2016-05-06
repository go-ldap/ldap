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
	fmt.Printf("I am: %s\n", res.AuthzId)
}

func ExampleWhoAmIProxied() {
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

	pa := ldap.NewProxyAuthControl("dn:uid=other,ou=people,dc=example,dc=org")

	res, err := conn.WhoAmI([]ldap.Control{pa})
	if err != nil {
		fmt.Errorf("Failed to call WhoAmI(): %s\n", err)
	}
	fmt.Printf("For this call only I am now: %s\n", res.AuthzId)
}
