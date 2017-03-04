// Package bungie provides a mechanism for using OAuth2 to access Bungie's API.
//
// See https://www.bungie.net/en/Help/Article/45481 for information on how to
// use Bungie's implementation of OAuth2.
//
// See bungie_test.go for an example of how to use this library.
package bungie

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/context"

	"github.com/zhirsch/oauth2"
	"github.com/zhirsch/oauth2/internal"
)

// Endpoint returns an oauth2.Endpoint for accessing Bungie's API.  The AuthURL
// varies for each user of Bungie's API, so it is provided as an argument.
func Endpoint(authURL string) oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:    authURL,
		TokenURL:   "https://www.bungie.net/Platform/App/GetAccessTokensFromCode/",
		RefreshURL: "https://www.bungie.net/Platform/App/GetAccessTokensFromRefreshToken/",
	}
}

// An Exchanger provides the implementation for using Bungie's OAuth2 API.
type Exchanger struct{}

// AuthCodeURL returns the URL for users to access to get the access code.
func (Exchanger) AuthCodeURL(c *oauth2.Config, state string, opts ...oauth2.AuthCodeOption) string {
	u, err := url.ParseRequestURI(c.Endpoint.AuthURL)
	if err != nil {
		panic(err)
	}
	q := u.Query()
	if state != "" {
		q["state"] = []string{state}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// RetrieveTokenWithPasswordCredentials is unimplemented for Bungie's API.
func (Exchanger) RetrieveTokenWithPasswordCredentials(ctx context.Context, c *oauth2.Config, username, password string) (*oauth2.Token, error) {
	panic("unsupported")
}

type retrieveTokenRequest struct {
	Code string `json:"code"`
}

type refreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type tokenResponse struct {
	Response struct {
		AccessToken struct {
			Value   string `json:"value"`
			ReadyIn int    `json:"readyin"`
			Expires int    `json:"expires"`
		} `json:"accessToken"`
		RefreshToken struct {
			Value   string `json:"value"`
			ReadyIn int    `json:"readyin"`
			Expires int    `json:"expires"`
		} `json:"refreshToken"`
		Scope int `json:"scope"`
	} `json:"Response"`

	ErrorCode       int         `json:"ErrorCode"`
	ThrottleSeconds int         `json:"ThrottleSeconds"`
	ErrorStatus     string      `json:"ErrorStatus"`
	Message         string      `json:"Message"`
	MessageData     interface{} `json:"MessageData"`
}

// RetrieveToken gets an authentication token from Bungie.
func (Exchanger) RetrieveToken(ctx context.Context, c *oauth2.Config, code string) (*oauth2.Token, error) {
	return getToken(ctx, c, c.Endpoint.TokenURL, retrieveTokenRequest{code})
}

// RefreshToken refreshes an authenticated token from Bungie.
func (Exchanger) RefreshToken(ctx context.Context, c *oauth2.Config, refreshToken string) (*oauth2.Token, error) {
	return getToken(ctx, c, c.Endpoint.RefreshURL, refreshTokenRequest{refreshToken})
}

func getToken(ctx context.Context, c *oauth2.Config, url string, body interface{}) (*oauth2.Token, error) {
	hc, err := internal.ContextClient(ctx)
	if err != nil {
		return nil, err
	}
	reqb, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(reqb))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	req.Header.Set("X-API-Key", c.ClientID)
	r, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	respb, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot retrieve token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, fmt.Errorf("oauth2: cannot retrieve token: %v\nResponse: %s", r.Status, body)
	}
	var token tokenResponse
	if err := json.Unmarshal(respb, &token); err != nil {
		return nil, err
	}
	if token.ErrorCode != 1 {
		return nil, fmt.Errorf("oauth2: cannot retrieve token: %+v", token)
	}
	return &oauth2.Token{
		AccessToken:  token.Response.AccessToken.Value,
		TokenType:    "Bearer",
		RefreshToken: token.Response.RefreshToken.Value,
		Expiry:       time.Now().Add(time.Duration(token.Response.AccessToken.Expires) * time.Second),
	}, nil
}
