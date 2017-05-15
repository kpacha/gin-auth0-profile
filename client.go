package auth0profile

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/patrickmn/go-cache"
)

// NewAuth0Client creates a new Auth0Client
func NewAuth0Client(domain string, TTL, cleanupInterval time.Duration) *Auth0Client {
	return &Auth0Client{
		fmt.Sprintf(Auth0TokenInfoPattern, domain),
		cache.New(TTL, cleanupInterval),
		TTL,
		Auth0ProfileContextKey,
	}
}

// Auth0Client builds gin middlewares
type Auth0Client struct {
	uri   string
	cache *cache.Cache
	ttl   time.Duration
	key   string
}

// Get returns the user profile from the local cache or the auth0 endpoint
func (j *Auth0Client) Get(jwt string) (Profile, error) {
	cacheKey := fmt.Sprintf("jwt-%s", jwt)
	if v, ok := j.cache.Get(cacheKey); ok {
		resp, ok := v.(Profile)
		if ok {
			return resp, nil
		}
	}

	data, err := j.requestCredentials(jwt)
	if err != nil {
		return data, err
	}

	j.cache.Set(cacheKey, data, j.ttl)
	return data, nil
}

func (j *Auth0Client) requestCredentials(jwt string) (Profile, error) {
	data := Profile{}
	req, err := j.prepareAuth0Request(jwt)
	if err != nil {
		return data, err
	}
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

func (j *Auth0Client) prepareAuth0Request(jwt string) (*http.Request, error) {
	body := strings.NewReader(fmt.Sprintf("{\"id_token\":\"%s\"}", jwt))
	req, err := http.NewRequest("POST", j.uri, body)
	if err != nil {
		return req, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, err
}
