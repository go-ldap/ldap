//go:build windows
// +build windows

package ldap

import (
	"log"

	"github.com/go-ldap/ldap/v3/gssapi"
)

// This example demonstrates passwordless bind using the current process' user
// credentials on Windows (SASL GSSAPI mechanism bind with SSPI client).
func ExampleConn_SSPIClient_GSSAPIBind() {
	// Windows only: Create a GSSAPIClient using Windows built-in SSPI lib
	// (secur32.dll).
	// This will use the credentials of the current process' user.
	sspiClient, err := gssapi.NewSSPIClient()
	if err != nil {
		log.Fatal(err)
	}
	defer sspiClient.Close()

	l, err := DialURL("ldap://ldap.example.com:389")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// Bind using supplied GSSAPIClient implementation
	err = l.GSSAPIBind(sspiClient, "ldap/ldap.example.com", "")
	if err != nil {
		log.Fatal(err)
	}
}
