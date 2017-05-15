package auth0profile

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const (
	// Auth0ProfileContextKey is the key for storing the profile into the request context
	Auth0ProfileContextKey = "auth0-user"
	// Auth0TokenInfoPattern is the pattern for building the url of the tokeninfo endpoint
	Auth0TokenInfoPattern = "https://%s.auth0.com/tokeninfo"
)

// ErrUnauthorized is the error used when the scope of profile doesn't match the restrictions
var ErrUnauthorized = fmt.Errorf("Error: unauthorized JWT")

type (
	// RoleMiddleware rejects requests from users without any of the receieved roles
	RoleMiddleware func(roles ...string) gin.HandlerFunc
	// TokenExtractor gets the JWT associated to the request as a string
	TokenExtractor func(c *gin.Context) string
)

// OAuth2TokenExtractor extracts the JWT from the authorization header
func OAuth2TokenExtractor(c *gin.Context) string {
	return strings.TrimPrefix(c.Request.Header.Get("Authorization"), "Bearer ")
}

// ContextTokenExtractor creates a TokenExtractor that gets the JWT from the context
func ContextTokenExtractor(key string) TokenExtractor {
	return func(c *gin.Context) string {
		v, ok := c.Get(key)
		if !ok {
			return ""
		}
		token := v.([]byte)
		return string(token)
	}
}

// RestrictTo creates a RoleMiddleware with the receieved auth0 client
func RestrictTo(client *Auth0Client) RoleMiddleware {
	return RestrictToWithKey(client, Auth0ProfileContextKey)
}

// RestrictToWithKey creates a RoleMiddleware with the receieved auth0 client and stores the profiles using
// the profileContextKey
func RestrictToWithKey(client *Auth0Client, profileContextKey string) RoleMiddleware {
	return RestrictToCustom(client, profileContextKey, OAuth2TokenExtractor)
}

// RestrictToCustom creates a RoleMiddleware with the receieved auth0 client. On each request, it extracts
// the JWT using the injected extactor and stores the profiles in the context with the profileContextKey
func RestrictToCustom(client *Auth0Client, profileContextKey string, extractor TokenExtractor) RoleMiddleware {
	return func(roles ...string) gin.HandlerFunc {
		if len(roles) == 0 {
			return func(c *gin.Context) { c.Next() }
		}
		roleDict := map[string]struct{}{}

		for _, role := range roles {
			roleDict[role] = struct{}{}
		}
		return func(c *gin.Context) {
			if c.Request.Method == "OPTIONS" {
				c.Next()
				return
			}

			data, err := client.Get(extractor(c))
			if err != nil {
				c.AbortWithError(http.StatusUnauthorized, err)
				return
			}

			if len(data.AppMetadata.Roles) == 0 {
				c.AbortWithStatus(http.StatusUnauthorized)
				return
			}

			if data.ContainsAnyRole(roleDict) {
				c.Set(profileContextKey, data)
				c.Next()
				return
			}

			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}
