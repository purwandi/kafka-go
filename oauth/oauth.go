// Package oauth provides OAuth 2.0 client-credentials authentication for
// kafka-go using the SASL OAUTHBEARER mechanism.
package oauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/segmentio/kafka-go/sasl"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// Config contains the OAuth 2.0 client-credentials parameters used to acquire
// an access token for Kafka authentication.
type Config struct {
	// TokenURL is the authorization server's token endpoint. Required.
	TokenURL string

	// ClientID and ClientSecret identify the OAuth client. Both are required.
	ClientID     string
	ClientSecret string

	// Scopes are joined with spaces and sent with the token request.
	Scopes []string

	// EndpointParams adds provider-specific parameters to the token request.
	EndpointParams url.Values

	// AuthStyle optionally controls how the client credentials are sent.
	// The zero value automatically detects the endpoint's preferred style.
	AuthStyle oauth2.AuthStyle

	// HTTPClient optionally overrides the HTTP client used to contact TokenURL.
	HTTPClient *http.Client

	// RefreshSkew causes a cached token to be refreshed this long before it
	// expires. The zero value defaults to 30 seconds.
	RefreshSkew time.Duration
}

// Mechanism implements sasl.Mechanism for OAuth 2.0 OAUTHBEARER. It reuses
// unexpired tokens between connections and refreshes them before expiration.
// It cannot renew authentication on an already-open Kafka connection.
type Mechanism struct {
	Config Config

	mu          sync.Mutex
	cachedToken *oauth2.Token
}

var _ sasl.Mechanism = (*Mechanism)(nil)

// Name returns "OAUTHBEARER".
func (*Mechanism) Name() string {
	return "OAUTHBEARER"
}

// Start obtains an access token and returns the initial OAUTHBEARER response.
func (m *Mechanism) Start(ctx context.Context) (sasl.StateMachine, []byte, error) {
	if err := m.Config.validate(); err != nil {
		return nil, nil, err
	}

	token, err := m.accessToken(ctx)
	if err != nil {
		return nil, nil, err
	}

	response := []byte("n,,\x01auth=Bearer " + token.AccessToken + "\x01\x01")
	return &session{}, response, nil
}

func (m *Mechanism) accessToken(ctx context.Context) (*oauth2.Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	refreshBefore := now.Add(m.Config.refreshSkew())
	if token := m.cachedToken; token != nil && !token.Expiry.IsZero() &&
		refreshBefore.Before(token.Expiry) {
		return token, nil
	}

	config := clientcredentials.Config{
		TokenURL:       m.Config.TokenURL,
		ClientID:       m.Config.ClientID,
		ClientSecret:   m.Config.ClientSecret,
		Scopes:         m.Config.Scopes,
		EndpointParams: m.Config.EndpointParams,
		AuthStyle:      m.Config.AuthStyle,
	}
	if m.Config.HTTPClient != nil {
		ctx = context.WithValue(ctx, oauth2.HTTPClient, m.Config.HTTPClient)
	}

	token, err := config.Token(ctx)
	if err != nil {
		return nil, fmt.Errorf("request oauth token: %w", err)
	}
	if !strings.EqualFold(token.TokenType, "Bearer") {
		return nil, fmt.Errorf("oauth token endpoint returned an unsupported token type")
	}
	if !validBearerToken(token.AccessToken) {
		return nil, fmt.Errorf("oauth token endpoint returned an invalid bearer token")
	}

	if !token.Expiry.IsZero() && refreshBefore.Before(token.Expiry) {
		m.cachedToken = token
	} else {
		m.cachedToken = nil
	}
	return token, nil
}

func (c Config) refreshSkew() time.Duration {
	if c.RefreshSkew == 0 {
		return 30 * time.Second
	}
	return c.RefreshSkew
}

func (c Config) validate() error {
	if c.TokenURL == "" {
		return fmt.Errorf("oauth token URL is required")
	}
	tokenURL, err := url.Parse(c.TokenURL)
	if err != nil || (tokenURL.Scheme != "https" && tokenURL.Scheme != "http") ||
		tokenURL.Hostname() == "" || tokenURL.User != nil || tokenURL.Fragment != "" {
		return fmt.Errorf("oauth token URL must be an absolute HTTP or HTTPS URL without user information or a fragment")
	}
	if c.ClientID == "" || c.ClientSecret == "" {
		return fmt.Errorf("oauth client ID and client secret are required")
	}
	if c.RefreshSkew < 0 {
		return fmt.Errorf("oauth refresh skew cannot be negative")
	}
	return nil
}

func validBearerToken(token string) bool {
	if token == "" {
		return false
	}

	padding := false
	hasData := false
	for _, char := range token {
		switch {
		case char >= 'a' && char <= 'z',
			char >= 'A' && char <= 'Z',
			char >= '0' && char <= '9',
			strings.ContainsRune("-._~+/", char):
			if padding {
				return false
			}
			hasData = true
		case char == '=':
			padding = true
		default:
			return false
		}
	}
	return hasData
}

type session struct {
	challenged bool
}

var _ sasl.StateMachine = (*session)(nil)

func (s *session) Next(_ context.Context, challenge []byte) (bool, []byte, error) {
	if len(challenge) != 0 {
		if s.challenged {
			return false, nil, fmt.Errorf("oauth bearer authentication failed")
		}
		s.challenged = true
		return false, []byte{}, nil
	}
	if s.challenged {
		return false, nil, fmt.Errorf("oauth bearer authentication failed")
	}
	return true, nil, nil
}
