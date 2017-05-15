package auth0profile

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
)

// Auth0Client defines the interface for the clients
type Auth0Client interface {
	Get(jwt string) (Profile, error)
}

// NewAuth0Client creates a new CachedAuth0Client
func NewAuth0Client(domain string, TTL, cleanupInterval time.Duration) *CachedAuth0Client {
	return &CachedAuth0Client{
		auth0Client{fmt.Sprintf(Auth0TokenInfoPattern, domain)},
		cache.New(TTL, cleanupInterval),
		TTL,
	}
}

// CachedAuth0Client returns the auth0 profile related to the received JWT from the local cache or
// from the injected Auth0Client
type CachedAuth0Client struct {
	client Auth0Client
	cache  *cache.Cache
	ttl    time.Duration
}

// Get returns the user profile from the local cache or the auth0 endpoint
func (j *CachedAuth0Client) Get(jwt string) (Profile, error) {
	cacheKey := fmt.Sprintf("jwt-%s", jwt)
	if v, ok := j.cache.Get(cacheKey); ok {
		resp, ok := v.(Profile)
		if ok {
			return resp, nil
		}
	}
	data, err := j.client.Get(jwt)
	if err != nil {
		return data, err
	}

	j.cache.Set(cacheKey, data, j.ttl)
	return data, nil
}

// auth0Client returns the auth0 profile related to the received JWT by asking the injected uri
type auth0Client struct {
	uri string
}

// Get returns the user profile from the auth0 endpoint
func (j auth0Client) Get(jwt string) (Profile, error) {
	data := Profile{}
	req, err := j.prepareAuth0Request(jwt)
	if err != nil {
		return data, err
	}
	return requestCredentials(req)
}

func (j auth0Client) prepareAuth0Request(jwt string) (*http.Request, error) {
	body := strings.NewReader(fmt.Sprintf("{\"id_token\":\"%s\"}", jwt))
	req, err := http.NewRequest("POST", j.uri, body)
	if err != nil {
		return req, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, err
}

func requestCredentials(req *http.Request) (Profile, error) {
	data := Profile{}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return data, err
	}
	if resp.StatusCode != http.StatusOK {
		return data, ErrUnauthorized
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return data, err
	}
	return data, nil
}
