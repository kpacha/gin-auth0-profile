package main

import (
	"flag"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/kpacha/gin-auth0-profile"
)

const (
	defaultAuth0Subdomain = "some.eu"
	defaultCacheTTL       = 5 * time.Minute
	defaultRoles          = "staff,manager"
)

func main() {
	auth0SubDomain := flag.String("auth0", defaultAuth0Subdomain, "subdomoain registered in auth0")
	roles := flag.String("roles", defaultRoles, "comma-separated list of allowed roles")
	cacheTTL := flag.Duration("cache", defaultCacheTTL, "TTL for the auth0 client cache")
	flag.Parse()

	jwtMiddleware := auth0profile.RestrictTo(auth0profile.JWTInfo(*auth0SubDomain, *cacheTTL, *cacheTTL))

	router := gin.Default()
	router.Use(jwtMiddleware(strings.Split(*roles, ",")...))

	router.GET("/", func(c *gin.Context) {
		p, ok := c.Get(auth0profile.Auth0ProfileContextKey)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		profile, ok := p.(auth0profile.Profile)
		if !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
		c.JSON(http.StatusOK, gin.H{"profile": profile})
	})
	router.Run(":8080")

}
