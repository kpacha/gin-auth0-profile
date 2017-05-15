package auth0profile

import "time"

// Profile is the structure returned by Auth0 with the user profile info
type Profile struct {
	ClientID       string      `json:"clientID"`
	GlobalClientID string      `json:"global_client_id"`
	UserID         string      `json:"user_id"`
	EmailVerified  bool        `json:"email_verified"`
	Email          string      `json:"email"`
	Name           string      `json:"name"`
	Picture        string      `json:"picture"`
	Nickname       string      `json:"nickname"`
	Locale         string      `json:"locale"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
	AppMetadata    AppMetadata `json:"app_metadata"`
}

// AppMetadata is the part of the profile the user can't edit
type AppMetadata struct {
	Roles []string `json:"roles"`
}

// ContainsAnyRole returns true if the profile contains any of the received roles in the
// app_metadata section
func (a *Profile) ContainsAnyRole(roleDict map[string]struct{}) bool {
	for _, r := range a.AppMetadata.Roles {
		if _, ok := roleDict[r]; ok {
			return true
		}
	}
	return false
}
