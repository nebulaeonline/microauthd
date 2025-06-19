// Package microauthd provides Go bindings for working with microauthd's
// admin and auth HTTP APIs.
package microauthd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// AuthClient handles token-based access to the auth API.
type AuthClient struct {
	BaseURL      string
	AccessToken  string
	RefreshToken string
	client       *http.Client
}

// NewAuthClient logs in using username/password and returns a ready client.
func NewAuthClient(baseURL, username, password, clientID string) (*AuthClient, error) {
	data := fmt.Sprintf("grant_type=password&username=%s&password=%s&client_id=%s",
		username, password, clientID)

	r, err := http.Post(
		baseURL+"/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(data),
	)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return nil, errors.New("login failed")
	}

	var resp TokenResponse
	err = json.NewDecoder(r.Body).Decode(&resp)
	if err != nil {
		return nil, err
	}

	return &AuthClient{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		client:       &http.Client{Timeout: 10 * time.Second},
	}, nil
}

func (a *AuthClient) authHeader() string {
	return fmt.Sprintf("Bearer %s", a.AccessToken)
}

// Me fetches the /me object for the authenticated user.
func (a *AuthClient) Me() (*MeResponse, error) {
	req, err := http.NewRequest("GET", a.BaseURL+"/me", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", a.authHeader())
	req.Header.Set("Accept", "application/json")

	res, err := a.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("me failed: %s", res.Status)
	}
	var me MeResponse
	err = json.NewDecoder(res.Body).Decode(&me)
	if err != nil {
		return nil, err
	}
	return &me, nil
}

// Refresh gets a new access token using the refresh token.
func (a *AuthClient) Refresh() error {
	if a.RefreshToken == "" {
		return errors.New("no refresh token available")
	}
	data := fmt.Sprintf("grant_type=refresh_token&refresh_token=%s", a.RefreshToken)
	r, err := http.Post(
		a.BaseURL+"/token",
		"application/x-www-form-urlencoded",
		strings.NewReader(data),
	)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh failed: %s", r.Status)
	}
	var resp TokenResponse
	err = json.NewDecoder(r.Body).Decode(&resp)
	if err != nil {
		return err
	}
	a.AccessToken = resp.AccessToken
	a.RefreshToken = resp.RefreshToken
	return nil
}

// Revoke revokes a token (default is self).
func (a *AuthClient) Revoke(token string) error {
	data := fmt.Sprintf("token=%s", token)
	req, err := http.NewRequest("POST", a.BaseURL+"/revoke", strings.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("revoke failed: %s\n%s", res.Status, string(b))
	}
	return nil
}
