package oauth2

import (
	"bytes"
	"net/url"
	"strings"

	"golang.org/x/net/context"

	"github.com/zhirsch/oauth2/internal"
)

// An Exchanger implements the functionality for getting and refreshing
// authentication tokens.
type Exchanger interface {
	// AuthCodeURL returns the URL for users to OAuth 2.0 provider's consent
	// page that asks for permissions for the required scopes explicitly.
	AuthCodeURL(c *Config, state string, opts ...AuthCodeOption) string

	// RetrieveTokenWithPasswordCredentials converts a resource owner
	// username and password pair into a token.
	RetrieveTokenWithPasswordCredentials(ctx context.Context, c *Config, username, password string) (*Token, error)

	// RetrieveToken converts an authorization code into a token.
	RetrieveToken(ctx context.Context, c *Config, code string) (*Token, error)

	// RefreshToken gets a new token for an expired token.
	RefreshToken(ctx context.Context, c *Config, refreshToken string) (*Token, error)
}

type defaultExchanger struct{}

func (defaultExchanger) AuthCodeURL(c *Config, state string, opts ...AuthCodeOption) string {
	var buf bytes.Buffer
	buf.WriteString(c.Endpoint.AuthURL)
	v := url.Values{
		"response_type": {"code"},
		"client_id":     {c.ClientID},
		"redirect_uri":  internal.CondVal(c.RedirectURL),
		"scope":         internal.CondVal(strings.Join(c.Scopes, " ")),
		"state":         internal.CondVal(state),
	}
	for _, opt := range opts {
		opt.setValue(v)
	}
	if strings.Contains(c.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(v.Encode())
	return buf.String()
}

func (defaultExchanger) RetrieveTokenWithPasswordCredentials(ctx context.Context, c *Config, username, password string) (*Token, error) {
	v := url.Values{
		"grant_type": {"password"},
		"username":   {username},
		"password":   {password},
		"scope":      internal.CondVal(strings.Join(c.Scopes, " ")),
	}
	tk, err := internal.RetrieveToken(ctx, c.ClientID, c.ClientSecret, c.Endpoint.TokenURL, v)
	if err != nil {
		return nil, err
	}
	if tk == nil {
		return nil, nil
	}
	return &Token{
		AccessToken:  tk.AccessToken,
		TokenType:    tk.TokenType,
		RefreshToken: tk.RefreshToken,
		Expiry:       tk.Expiry,
		raw:          tk.Raw,
	}, nil
}

func (defaultExchanger) RetrieveToken(ctx context.Context, c *Config, code string) (*Token, error) {
	v := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": internal.CondVal(c.RedirectURL),
	}
	tk, err := internal.RetrieveToken(ctx, c.ClientID, c.ClientSecret, c.Endpoint.TokenURL, v)
	if err != nil {
		return nil, err
	}
	if tk == nil {
		return nil, nil
	}
	return &Token{
		AccessToken:  tk.AccessToken,
		TokenType:    tk.TokenType,
		RefreshToken: tk.RefreshToken,
		Expiry:       tk.Expiry,
		raw:          tk.Raw,
	}, nil
}

func (defaultExchanger) RefreshToken(ctx context.Context, c *Config, refreshToken string) (*Token, error) {
	v := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	url := c.Endpoint.RefreshURL
	if url == "" {
		url = c.Endpoint.TokenURL
	}
	tk, err := internal.RetrieveToken(ctx, c.ClientID, c.ClientSecret, url, v)
	if err != nil {
		return nil, err
	}
	if tk == nil {
		return nil, nil
	}
	return &Token{
		AccessToken:  tk.AccessToken,
		TokenType:    tk.TokenType,
		RefreshToken: tk.RefreshToken,
		Expiry:       tk.Expiry,
		raw:          tk.Raw,
	}, nil
}
