package ldap

import (
	"testing"
)

func TestExtendedRequest_WhoAmI(t *testing.T) {
	l, err := DialURL(ldapServer)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}
	defer l.Close()

	l.Bind("", "") // anonymous
	defer l.Unbind()

	rfc4532req := NewExtendedRequest("1.3.6.1.4.1.4203.1.11.3", nil) // request value is <nil>

	var rfc4532resp *ExtendedResponse
	if rfc4532resp, err = l.Extended(rfc4532req); err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}
	t.Logf("%#v\n", rfc4532resp)
}

func TestExtendedRequest_FastBind(t *testing.T) {
	conn, err := DialURL(ldapServer)
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()

	request := NewExtendedRequest("1.3.6.1.4.1.4203.1.11.3", nil)
	_, err = conn.Extended(request)
	if err != nil {
		t.Errorf("%s failed: %v", t.Name(), err)
		return
	}
}
