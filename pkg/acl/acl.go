package acl

import (
	"io"
	"log"
	"net/http"

	"gopkg.in/yaml.v3"
)

type ACL struct {
	Rules []Rule
}

func Read(r io.Reader) (*ACL, error) {
	acl := ACL{}
	ydec := yaml.NewDecoder(r)
	if err := ydec.Decode(&acl); err != nil {
		return nil, err
	}
	if err := acl.CompileURLs(); err != nil {
		return nil, err
	}
	return &acl, nil
}

// CompileURLs compiles regular expressions for all URLs.
func (acl *ACL) CompileURLs() error {
	for i := range acl.Rules {
		rule := &acl.Rules[i]
		if err := rule.CompileURL(); err != nil {
			return err
		}
	}
	return nil
}

func (acl *ACL) Match(req *http.Request) Action {
	for _, rule := range acl.Rules {
		log.Println(rule)
		if rule.Match(req) {
			return rule.Action
		}
	}
	return Deny
}
