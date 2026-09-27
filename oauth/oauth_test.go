package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestMechanism_Start(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		tokenType  string
		access     string
		wantError  string
	}{
		{
			name:       "valid token",
			statusCode: http.StatusOK,
			tokenType:  "Bearer",
			access:     "access-token_123",
		},
		{
			name:       "unsupported token type",
			statusCode: http.StatusOK,
			tokenType:  "MAC",
			access:     "access-token",
			wantError:  "unsupported token type",
		},
		{
			name:       "invalid token",
			statusCode: http.StatusOK,
			tokenType:  "Bearer",
			access:     "token\x01injected",
			wantError:  "invalid bearer token",
		},
		{
			name:       "token endpoint error",
			statusCode: http.StatusUnauthorized,
			wantError:  "request oauth token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method = %q, want POST", r.Method)
				}
				if got := r.FormValue("grant_type"); got != "client_credentials" {
					t.Errorf("grant_type = %q, want client_credentials", got)
				}
				if got := r.FormValue("scope"); got != "kafka.read kafka.write" {
					t.Errorf("scope = %q, want kafka.read kafka.write", got)
				}
				if got := r.FormValue("audience"); got != "tenant-1" {
					t.Errorf("audience = %q, want tenant-1", got)
				}
				username, password, ok := r.BasicAuth()
				if !ok || username != "client-id" || password != "client-secret" {
					t.Errorf("unexpected Basic authentication credentials")
				}

				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				if tt.statusCode == http.StatusOK {
					if err := json.NewEncoder(w).Encode(map[string]any{
						"access_token": tt.access,
						"token_type":   tt.tokenType,
						"expires_in":   3600,
					}); err != nil {
						t.Errorf("encode token response: %v", err)
					}
				}
			}))
			defer server.Close()

			mechanism := &Mechanism{Config: Config{
				TokenURL:       server.URL,
				ClientID:       "client-id",
				ClientSecret:   "client-secret",
				Scopes:         []string{"kafka.read", "kafka.write"},
				EndpointParams: url.Values{"audience": {"tenant-1"}},
				AuthStyle:      oauth2.AuthStyleInHeader,
			}}

			machine, initial, err := mechanism.Start(context.Background())
			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				require.Nil(t, machine)
				require.Nil(t, initial)
				return
			}

			require.NoError(t, err)
			require.Equal(t, []byte("n,,\x01auth=Bearer access-token_123\x01\x01"), initial)
			done, response, err := machine.Next(context.Background(), nil)
			require.NoError(t, err)
			require.True(t, done)
			require.Nil(t, response)
		})
	}
}

func TestMechanism_Start_InvalidConfig(t *testing.T) {
	tests := []struct {
		name   string
		config Config
		want   string
	}{
		{
			name: "missing URL",
			config: Config{
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			want: "token URL is required",
		},
		{
			name: "invalid URL",
			config: Config{
				TokenURL:     "file:///token",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			want: "absolute HTTP or HTTPS URL",
		},
		{
			name: "URL contains credentials",
			config: Config{
				TokenURL:     "https://user:password@example.com/token",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
			},
			want: "absolute HTTP or HTTPS URL",
		},
		{
			name: "missing client credentials",
			config: Config{
				TokenURL: "https://example.com/token",
			},
			want: "client ID and client secret are required",
		},
		{
			name: "negative refresh skew",
			config: Config{
				TokenURL:     "https://example.com/token",
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RefreshSkew:  -time.Second,
			},
			want: "refresh skew cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			machine, response, err := (&Mechanism{Config: tt.config}).Start(context.Background())
			require.ErrorContains(t, err, tt.want)
			require.Nil(t, machine)
			require.Nil(t, response)
		})
	}
}

func TestMechanism_Start_TokenExpiryRefresh(t *testing.T) {
	tests := []struct {
		name               string
		refreshSkew        time.Duration
		expiredCachedToken bool
		wantCalls          int32
	}{
		{
			name:      "reuses token before refresh window",
			wantCalls: 1,
		},
		{
			name:               "replaces expired cached token",
			expiredCachedToken: true,
			wantCalls:          1,
		},
		{
			name:        "refreshes token inside refresh window",
			refreshSkew: 2 * time.Hour,
			wantCalls:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tokenRequests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tokenRequests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(map[string]any{
					"access_token": "access-token",
					"token_type":   "Bearer",
					"expires_in":   3600,
				}); err != nil {
					t.Errorf("encode token response: %v", err)
				}
			}))
			defer server.Close()

			mechanism := &Mechanism{Config: Config{
				TokenURL:     server.URL,
				ClientID:     "client-id",
				ClientSecret: "client-secret",
				RefreshSkew:  tt.refreshSkew,
			}}
			if tt.expiredCachedToken {
				mechanism.cachedToken = &oauth2.Token{
					AccessToken: "expired-token",
					TokenType:   "Bearer",
					Expiry:      time.Now().Add(-time.Second),
				}
			}
			for range 2 {
				_, _, err := mechanism.Start(context.Background())
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantCalls, tokenRequests.Load())
		})
	}
}

func TestSession_Next_Challenge(t *testing.T) {
	machine := &session{}
	done, response, err := machine.Next(context.Background(), []byte(`{"status":"invalid_token"}`))
	require.NoError(t, err)
	require.False(t, done)
	require.NotNil(t, response)
	require.Empty(t, response)

	done, response, err = machine.Next(context.Background(), nil)
	require.ErrorContains(t, err, "oauth bearer authentication failed")
	require.False(t, done)
	require.Nil(t, response)
}

func TestValidBearerToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
		valid bool
	}{
		{name: "opaque token", token: "abc.DEF-123_~+/", valid: true},
		{name: "padded token", token: "abc==", valid: true},
		{name: "padding only", token: "=="},
		{name: "empty token"},
		{name: "space", token: "abc def"},
		{name: "control character", token: "abc\x01def"},
		{name: "padding before content", token: "abc=def"},
		{name: "unicode", token: "tökén"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.valid, validBearerToken(tt.token))
		})
	}
}

func TestMechanism_Start_UsesContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mechanism := &Mechanism{Config: Config{
		TokenURL:     "https://example.com/token",
		ClientID:     "client-id",
		ClientSecret: "client-secret",
	}}
	_, _, err := mechanism.Start(ctx)
	require.ErrorContains(t, err, "request oauth token")
}
