package acl

import "net/url"

type URL struct {
	*url.URL
}

func (u *URL) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	nu, err := url.Parse(s)
	u.URL = nu
	return err
}
