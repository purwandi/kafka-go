package oauth_test

import (
	"crypto/tls"
	"net/http"
	"os"
	"time"

	"github.com/purwandi/kafka-go/oauth"
	"github.com/segmentio/kafka-go"
)

func ExampleMechanism() {
	mechanism := &oauth.Mechanism{
		Config: oauth.Config{
			TokenURL:     "https://identity.example.com/oauth/token",
			ClientID:     "kafka-consumer",
			ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
			Scopes:       []string{"kafka.read"},
			HTTPClient:   &http.Client{Timeout: 10 * time.Second},
		},
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: []string{"broker1.example.com:9093"},
		GroupID: "consumer-group",
		Topic:   "events",
		Dialer: &kafka.Dialer{
			Timeout:       10 * time.Second,
			SASLMechanism: mechanism,
			TLS:           &tls.Config{},
		},
	})
	defer reader.Close()
}
