package auth0profile

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/patrickmn/go-cache"
)

func TestCachedAuth0Client_okFromCache(t *testing.T) {
	jwt := "some"
	expectedProfile := Profile{AppMetadata: AppMetadata{Roles: []string{"one"}}}
	ttl := 5 * time.Minute
	localCache := cache.New(ttl, ttl)
	client := CachedAuth0Client{
		dummyClient(expectedProfile),
		localCache,
		ttl,
	}
	localCache.Set("jwt-some", expectedProfile, ttl)
	profile, err := client.Get(jwt)
	if err != nil {
		t.Error("Error getting the profile from the cache. Got:", err.Error())
	}
	if profile.AppMetadata.Roles[0] != expectedProfile.AppMetadata.Roles[0] {
		t.Error("Wring profile received from the cache:", profile)
	}
}

func TestCachedAuth0Client_koWrongType(t *testing.T) {
	jwt := "some"
	ttl := 5 * time.Minute
	localCache := cache.New(ttl, ttl)
	expectedError := fmt.Errorf("boom")
	client := CachedAuth0Client{
		explosiveClient{expectedError},
		localCache,
		ttl,
	}
	localCache.Set("jwt-some", true, ttl)
	profile, err := client.Get(jwt)
	if err != expectedError {
		t.Error("Error getting the profile from the cache. Got:", err)
	}
	if len(profile.AppMetadata.Roles) != 0 {
		t.Error("Wrong profile received from the cache:", profile)
	}
}

func TestCachedAuth0Client_okFromClient(t *testing.T) {
	jwt := "some"
	expectedProfile := Profile{AppMetadata: AppMetadata{Roles: []string{"one"}}}
	ttl := 5 * time.Minute
	localCache := cache.New(ttl, ttl)
	client := CachedAuth0Client{
		dummyClient(expectedProfile),
		localCache,
		ttl,
	}
	profile, err := client.Get(jwt)
	if err != nil {
		t.Error("Error getting the profile from the cache. Got:", err.Error())
	}
	if profile.AppMetadata.Roles[0] != expectedProfile.AppMetadata.Roles[0] {
		t.Error("Wrong profile received from the cache:", profile)
	}
}

func TestAuth0Client_ok(t *testing.T) {
	jwt := "some"
	server := httptest.NewServer(dummyHandler{t, jwt, http.StatusOK, defaultBody})
	defer server.Close()

	client := auth0Client{server.URL}
	profile, err := client.Get(jwt)
	if err != nil {
		t.Error("Error getting the profile from the client. Got:", err.Error())
	}
	if profile.AppMetadata.Roles[0] != "role1" {
		t.Error("Wrong profile received from the client:", profile)
	}
}

func TestAuth0Client_koResponse(t *testing.T) {
	jwt := "some"
	server := httptest.NewServer(dummyHandler{t, jwt, http.StatusInternalServerError, defaultBody})
	defer server.Close()

	client := auth0Client{server.URL}
	if _, err := client.Get(jwt); err != ErrUnauthorized {
		t.Error("Unexpected error getting the profile from the client. Got:", err)
	}
}

func TestAuth0Client_wrongResponse(t *testing.T) {
	jwt := "some"
	server := httptest.NewServer(dummyHandler{t, jwt, http.StatusOK, ""})
	defer server.Close()

	client := auth0Client{server.URL}
	if _, err := client.Get(jwt); err != io.EOF {
		t.Error("Unexpected error getting the profile from the client. Got:", err)
	}
}

type dummyClient Profile

func (d dummyClient) Get(_ string) (Profile, error) { return Profile(d), nil }

type explosiveClient struct {
	err error
}

func (e explosiveClient) Get(_ string) (Profile, error) { return Profile{}, e.err }

const (
	defaultBody = `{
			"clientID":"abc",
			"global_client_id":"abcdefg",
			"email_verified":true,
			"app_metadata":{
				"roles":["role1"]
			}
		}`
)

type dummyHandler struct {
	t      *testing.T
	token  string
	status int
	body   string
}

func (h dummyHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	body, _ := ioutil.ReadAll(req.Body)
	req.Body.Close()
	expected := fmt.Sprintf("{\"id_token\":\"%s\"}", h.token)
	if expected != string(body) {
		h.t.Errorf("Wrong request body. got: %s. want: %s", string(body), expected)
	}
	rw.WriteHeader(h.status)
	rw.Header().Set("Content-type", "application/json")
	fmt.Fprintln(rw, h.body)
}
