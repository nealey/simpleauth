package acl

import (
	"net/http"
	"net/url"
	"regexp"
)

type Rule struct {
	URL       string
	urlRegexp *regexp.Regexp
	Users     []string
	Methods   []string
	Action    Action
}

// CompileURL compiles regular expressions for the URL.
// This is an startup optimization that speeds up rule processing.
func (r *Rule) CompileURL() error {
	if re, err := regexp.Compile(r.URL); err != nil {
		return err
	} else {
		r.urlRegexp = re
	}
	return nil
}

// Match returns true if req is matched by the rule
func (r *Rule) Match(req *http.Request) bool {
	if r.urlRegexp == nil {
		// Womp womp. Things will be slow, because the compiled regex won't get cached.
		r.CompileURL()
	}
	requestUser := req.URL.User.Username()
	anonURL := url.URL(*req.URL)
	anonURL.User = nil
	found := r.urlRegexp.FindStringSubmatch(anonURL.String())
	if len(found) == 0 {
		return false
	}

	// Match any listed method
	methodMatch := (len(r.Methods) == 0)
	for _, method := range r.Methods {
		if method == req.Method {
			methodMatch = true
		}
	}
	if !methodMatch {
		return false
	}

	// If they used (?P<user>),
	// make sure that matches the username in the request URL
	userIndex := r.urlRegexp.SubexpIndex("user")
	if (userIndex != -1) && (found[userIndex] != requestUser) {
		return false
	}

	// Match any listed user
	userMatch := (len(r.Users) == 0)
	for _, user := range r.Users {
		if user == requestUser {
			userMatch = true
		}
	}
	if !userMatch {
		// If no user match
		return false
	}

	return true
}
