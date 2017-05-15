package auth0profile

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRestrictTo_ok(t *testing.T) {
	router := gin.New()
	router.Use(RestrictTo(dummyClient(Profile{AppMetadata: AppMetadata{Roles: []string{"role1"}}}))("role1"))
	router.GET("/", func(c *gin.Context) {
		p, ok := c.Get(Auth0ProfileContextKey)
		if !ok {
			t.Error("The profile is not in the context")
			return
		}
		profile, ok := p.(Profile)
		if !ok {
			t.Error("The stored data is not a profile")
			return
		}
		if len(profile.AppMetadata.Roles) != 1 {
			t.Errorf("unexpected profile. got: %v", profile)
		}
		c.JSON(http.StatusOK, gin.H{"alive": true})
	})

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "BEARER something")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	expected := "{\"alive\":true}\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestRestrictTo_koUnauthorized(t *testing.T) {
	router := gin.New()
	router.Use(RestrictTo(dummyClient(Profile{AppMetadata: AppMetadata{Roles: []string{"role1"}}}))("role2"))
	router.GET("/", func(c *gin.Context) {
		t.Error("This handler shouldn't be called")
	})

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "BEARER something")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}
}

func TestRestrictTo_koNoRoles(t *testing.T) {
	router := gin.New()
	router.Use(RestrictTo(dummyClient(Profile{}))("role2"))
	router.GET("/", func(c *gin.Context) {
		t.Error("This handler shouldn't be called")
	})

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "BEARER something")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}
}

func TestRestrictTo_koClientError(t *testing.T) {
	expectedErr := fmt.Errorf("boom")
	router := gin.New()
	router.Use(RestrictTo(explosiveClient{expectedErr})("role1"))
	router.GET("/", func(c *gin.Context) {
		t.Error("This handler shouldn't be called")
	})

	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Add("Authorization", "BEARER something")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusUnauthorized {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusUnauthorized)
	}
}

func TestRestrictTo_options(t *testing.T) {
	router := gin.New()
	router.Use(RestrictTo(dummyClient(Profile{}))("role1"))
	router.OPTIONS("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"alive": true})
	})

	req, _ := http.NewRequest("OPTIONS", "/", nil)
	req.Header.Add("Authorization", "BEARER something")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	expected := "{\"alive\":true}\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

func TestRestrictTo_fromContext(t *testing.T) {
	tokenKey := "some-key-for-the-token"
	tokenBody := "a_very_long_JWT_token"

	client := spyClient{Profile{AppMetadata: AppMetadata{Roles: []string{"role1"}}}, tokenBody, fmt.Errorf("never to see")}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set(tokenKey, []byte(tokenBody))
	})
	router.Use(RestrictToCustom(client, Auth0ProfileContextKey, ContextTokenExtractor(tokenKey))("role1"))
	router.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"alive": true})
	})

	req, _ := http.NewRequest("GET", "/", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	expected := "{\"alive\":true}\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}

type spyClient struct {
	Value    Profile
	Expected string
	Err      error
}

func (c spyClient) Get(jwt string) (Profile, error) {
	if jwt != c.Expected {
		return Profile{}, c.Err
	}
	return c.Value, nil
}

func TestRestrictTo_noRoles(t *testing.T) {
	router := gin.New()
	router.Use(RestrictTo(explosiveClient{fmt.Errorf("this should not be called")})())
	router.OPTIONS("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"alive": true})
	})

	req, _ := http.NewRequest("OPTIONS", "/", nil)
	req.Header.Add("Authorization", "BEARER something")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v",
			status, http.StatusOK)
	}
	expected := "{\"alive\":true}\n"
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}
}
