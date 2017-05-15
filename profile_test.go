package auth0profile

import "testing"

func TestProfileContainsAnyRole(t *testing.T) {
	p := Profile{AppMetadata: AppMetadata{Roles: []string{"one", "some", "more"}}}
	if ok := p.ContainsAnyRole(map[string]struct{}{"one": struct{}{}}); !ok {
		t.Error("Error getting the role from the profile")
	}
	if ok := p.ContainsAnyRole(map[string]struct{}{"two": struct{}{}}); ok {
		t.Error("There is a phantom role in the profile")
	}
	if ok := p.ContainsAnyRole(map[string]struct{}{"some": struct{}{}, "two": struct{}{}}); !ok {
		t.Error("Error getting the role from the profile")
	}
}
