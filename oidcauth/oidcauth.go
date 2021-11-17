package oidcauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/zalando/go-keyring"
	"golang.org/x/oauth2"
)

type Client struct {
	issuer, clientID string
	m                *sync.Mutex
	oauth2Config     oauth2.Config
	provider         *oidc.Provider
}

var (
	ErrNotOAuth2Transport = errors.New("http client's transport is not an oauth2.Transport")
)

// New creates a new oidc client for login, using context.Background as context for endpoint discovery.
// The oidc client autoregisters the "openid" scope in scopes, so only additional scopes have to be specified.
func New(issuer, clientID string, scopes ...string) (*Client, error) {
	return NewWithContext(context.Background(), issuer, clientID, scopes...)
}

// NewWithContext creates a new oidc client for login, using ctx for endpoint discovery.
// The oidc client autoregisters the "openid" scope in scopes, so only additional scopes have to be specified.
func NewWithContext(ctx context.Context, issuer, clientID string, scopes ...string) (*Client, error) {
	issuer = strings.TrimRight(issuer, "/")
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}

	scopes = append(scopes, oidc.ScopeOpenID)

	return &Client{
		m:        &sync.Mutex{},
		clientID: clientID,
		issuer:   issuer,
		provider: provider,
		oauth2Config: oauth2.Config{
			ClientID: clientID,
			// Discovery returns the OAuth2 endpoints.
			Endpoint: provider.Endpoint(),
			// "openid" is a required scope for OpenID Connect flows.
			Scopes: scopes,
		},
	}, nil
}

// LoginWithCache tries to retrieve a refresh token from the system's keyring if present.
// If that fails, a browser based login to the oidc issuer is triggered to retrieve a token using loginContext.
// A http client is then build using httpClientContext as its context and the token for providing automated authentication and refresh.
// For documentation on the used keyring see StoreTokenInCache.
func (c *Client) LoginWithCache(loginContext, httpClientContext context.Context) (*http.Client, error) {
	token, err := getTokenFromKeyring(c.issuer, c.clientID)
	if err != nil {
		return nil, err
	}

	if token == nil {
		token, err = c.BrowserLogin(loginContext)
		if err != nil {
			return nil, err
		}
	}

	return c.oauth2Config.Client(httpClientContext, token), nil
}

func getTokenFromKeyring(issuer, clientID string) (*oauth2.Token, error) {
	refreshToken, err := keyring.Get(issuer, clientID)
	if err != nil {
		return nil, err
	}

	return &oauth2.Token{
		RefreshToken: refreshToken,
	}, nil
}

// StoreTokenInCache extracts an oauth2 token from the http clients transport layer (provided it is a *oauth2.Transport).
// The token's refresh token is then stored in the system's keyring.
// The keyring used is chosen based on GOOS:
//     Linux: DBus Secret Service (needs default collection "login")
//     Darwin: /usr/bin/security (OS X keychain)
//     Windows: Windows Credential Manager
func (c *Client) StoreTokenInCache(client *http.Client) error {
	transport, ok := client.Transport.(*oauth2.Transport)
	if !ok {
		return ErrNotOAuth2Transport
	}
	token, err := transport.Source.Token()
	if err != nil {
		return err
	}

	return keyring.Set(c.issuer, c.clientID, token.RefreshToken)
}

// DeleteTokenFromKeyring deletes a refresh token associated with the client's issuer and clientID from the system's keyring.
func (c *Client) DeleteTokenFromKeyring() error {
	return keyring.Delete(c.issuer, c.clientID)
}

// BrowserLogin triggers a login with the client's oidc issuer in the system's browser and returns the retrieved token.
// loginContext is used for the code to token exchange with the issuer.
// For opening the browser the following is used according to GOOS:
//     Linux: xdg-open url
//     Windows: cmd /c start url
//     Darwin: open url
func (c *Client) BrowserLogin(loginContext context.Context) (*oauth2.Token, error) {
	c.m.Lock()
	defer c.m.Unlock()
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, fmt.Errorf("unable to start localhost listener")
	}

	port := listener.Addr().(*net.TCPAddr).Port

	c.oauth2Config.RedirectURL = fmt.Sprintf("http://localhost:%d/callback", port)

	state := uuid.New()

	err = openBrowser(c.oauth2Config.AuthCodeURL(state.String()))
	if err != nil {
		return nil, fmt.Errorf("failed at opening browser: %w", err)
	}

	var httpError error
	var token *oauth2.Token
	http.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state.String() {
			httpError = fmt.Errorf("state does not match")
			return
		}

		oauth2Token, err := c.oauth2Config.Exchange(loginContext, r.URL.Query().Get("code"))
		if err != nil {
			httpError = fmt.Errorf("failed to exchange token: %w", err)
			return
		}

		token = oauth2Token
	})

	if err = http.Serve(listener, nil); err != nil {
		return nil, err
	}

	if httpError != nil {
		return nil, httpError
	}

	return token, nil
}

func openBrowser(url string) error {
	var args []string
	switch runtime.GOOS {
	case "darwin":
		args = []string{"open"}
	case "windows":
		args = []string{"cmd", "/c", "start"}
	default:
		args = []string{"xdg-open"}
	}
	cmd := exec.Command(args[0], append(args[1:], url)...)
	return cmd.Start()
}
