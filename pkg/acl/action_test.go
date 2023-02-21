package acl

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestActions(t *testing.T) {
	if Deny.String() != "deny" {
		t.Error("Deny string wrong")
	}
	if Auth.String() != "auth" {
		t.Error("Auth string wrong")
	}
	if Public.String() != "public" {
		t.Error("Public string wrong")
	}
}

func TestYamlActions(t *testing.T) {
	var out []Action
	yamlDoc := "[Deny, Auth, Public, dEnY, pUBLiC]"
	expected := []Action{Deny, Auth, Public, Deny, Public}
	if err := yaml.Unmarshal([]byte(yamlDoc), &out); err != nil {
		t.Fatal(err)
	}

	if len(out) != len(expected) {
		t.Error("Wrong length of unmarshalled yaml")
	}

	for i, a := range out {
		if expected[i] != a {
			t.Errorf("Wrong value at position %d. Wanted %v, got %v", i, expected[i], a)
		}
	}
}
