package acl

import (
	"fmt"
	"strings"
)

type Action int

const (
	Deny Action = iota
	Auth
	Public
)

var actions = [...]string{
	"deny",
	"auth",
	"public",
}

func (a Action) String() string {
	return actions[a]
}

func (a *Action) UnmarshalYAML(unmarshal func(any) error) error {
	var val string
	if err := unmarshal(&val); err != nil {
		return err
	}
	val = strings.ToLower(val)

	for i, s := range actions {
		if val == s {
			*a = (Action)(i)
			return nil
		}
	}
	return fmt.Errorf("Unknown action type: %s", val)
}
