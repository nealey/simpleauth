package acl

import (
	"net/http"
	"net/url"
	"os"
	"testing"
)

type testAcl struct {
	t   *testing.T
	acl *ACL
}

func readAcl(filename string) (*ACL, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	acl, err := Read(f)
	if err != nil {
		return nil, err
	}
	return acl, nil
}

func (ta *testAcl) try(method string, URL string, expected Action) {
	u, err := url.Parse(URL)
	if err != nil {
		ta.t.Errorf("Parsing %s: %v", URL, err)
	}
	req := &http.Request{
		Method: method,
		URL:    u,
	}
	action := ta.acl.Match(req)
	if action != expected {
		ta.t.Errorf("%s %s expected %v but got %v", method, URL, expected, action)
	}
}

func TestRegexen(t *testing.T) {
	acl, err := readAcl("testdata/acl.yaml")
	if err != nil {
		t.Fatal(err)
	}

	for i, rule := range acl.Rules {
		if rule.urlRegexp == nil {
			t.Errorf("Regexp not precompiled on rule %d", i)
		}
	}
}

func TestUsers(t *testing.T) {
	acl, err := readAcl("testdata/acl.yaml")
	if err != nil {
		t.Fatal(err)
	}

	if acl.Rules[0].Users != nil {
		t.Errorf("Rules[0].Users != nil")
	}
	if acl.Rules[1].Users == nil {
		t.Errorf("Rules[0].Users == nil")
	}
}

func TestAclMatching(t *testing.T) {
	acl, err := readAcl("testdata/acl.yaml")
	if err != nil {
		t.Fatal(err)
	}
	ta := testAcl{
		t:   t,
		acl: acl,
	}

	ta.try("GET", "https://example.com/moo", Deny)
	ta.try("GET", "https://example.com/blargh", Deny)
	ta.try("GET", "https://example.com/public/moo", Public)
	ta.try("BLARGH", "https://example.com/blargh", Public)
	ta.try("GET", "https://example.com/only-alice/boog", Deny)
	ta.try("GET", "https://alice:@example.com/only-alice/boog", Auth)
	ta.try("GET", "https://alice:@example.com/bob/", Deny)
	ta.try("GET", "https://bob:@example.com/bob/", Auth)
}
