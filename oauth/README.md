# sasl/oauth

OAuth 2.0 client-credentials authentication for
[`kafka-go`](https://github.com/segmentio/kafka-go), using the SASL
`OAUTHBEARER` mechanism.

## Install

Run this from your Go project:

```bash
go get github.com/purwandi/kafka-go/oauth@latest
```

## Configure a reader

The client caches the access token between Kafka connections and requests a new
one before the cached token expires. By default, it refreshes tokens within 30
seconds of expiration.

```go
package main

import (
	"crypto/tls"
	"net/http"
	"os"
	"time"

	"github.com/purwandi/kafka-go/oauth"
	"github.com/segmentio/kafka-go"
)

func main() {
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
```

For a writer, pass the mechanism as `kafka.Transport.SASL`:

```go
writer := &kafka.Writer{
	Addr:     kafka.TCP("broker1.example.com:9093"),
	Topic:    "events",
	Balancer: &kafka.Hash{},
	Transport: &kafka.Transport{
		SASL: mechanism,
		TLS:  &tls.Config{},
	},
}
defer writer.Close()
```

## Configuration reference

| Field            | Description                                                                                        |
|------------------|----------------------------------------------------------------------------------------------------|
| `TokenURL`       | OAuth token endpoint URL. HTTP and HTTPS are accepted; use HTTPS outside local development.        |
| `ClientID`       | OAuth client identifier.                                                                           |
| `ClientSecret`   | OAuth client secret. Read it from an environment variable or secret store.                         |
| `Scopes`         | Optional scopes requested using the space-separated `scope` parameter.                             |
| `EndpointParams` | Optional provider-specific token request parameters, such as `audience`.                           |
| `AuthStyle`      | Optional `oauth2.AuthStyle`; zero value auto-detects Basic authentication versus form credentials. |
| `HTTPClient`     | Optional client for the token endpoint. Configure a timeout when supplying one.                    |
| `RefreshSkew`    | Optional early-refresh window. Defaults to 30 seconds; tokens without an expiry are not cached.    |

The mechanism implements `sasl.Mechanism` and can be used with a
`kafka.Dialer` or `kafka.Transport`. Protect Kafka traffic with TLS; SASL
authentication does not encrypt the Kafka connection. Token refresh takes
effect on new SASL authentications. `kafka-go` does not reauthenticate an
already-open connection, so an active connection is not renewed when its token
expires.

An expired access token does not usually interrupt a Kafka connection that has
already authenticated: brokers typically validate the token during SASL
authentication, not for every message. The connection may therefore continue
to consume or publish while it remains open. Behavior depends on broker policy:
if the broker closes the connection or requires reauthentication, this
`kafka-go` version does not reauthenticate that active connection. The client
must establish a new connection and authenticate again, which can briefly
pause consuming or cause a publish call to return an error.

## Handling an expired token while running

The OAuth mechanism cannot refresh SASL authentication on a connection that is
already open. Token expiration alone may not affect an established connection;
the broker's policy determines how long that connection remains usable. If the
broker closes a connection, `kafka-go` may establish a new connection; the
mechanism then uses a fresh token if the cached token has expired or entered
the refresh window. Read and write calls can still return an error, so
applications should handle those errors explicitly.

### Keep the application running during reconnects

Keep one long-lived `Reader` and `Writer`; do not close and recreate them just
because a token expired. `kafka-go` owns the broker connections. A new
connection performs SASL authentication again, and the OAuth mechanism supplies
a refreshed token when needed.

For readers, `kafka-go` retries partition-reader initialization and resumes
from the current offset. A consumer group may pause while it rejoins or
rebalances. Keep calling `FetchMessage` on the same reader after a transient
read error, and commit only after processing succeeds, as shown below.

For writers, `kafka-go` retries temporary write/network failures up to
`Writer.MaxAttempts` (10 by default). If `WriteMessages` still returns an
error, retry the same message using the same long-lived writer. The next
attempt can use a newly established broker connection. Do not create a new
writer per message or per retry.

Reconnect is not a guarantee of zero interruption: reads can pause, and a
write can return an error during recovery. To keep a request handler or other
application work from waiting on Kafka, place publishing behind a bounded
queue and let a background worker retry. A bounded in-memory queue only
absorbs short outages; use a durable outbox if messages must survive process
restarts or a prolonged Kafka outage. When the queue fills, apply backpressure
or reject/ persist the event explicitly rather than silently dropping it.

### Consumer

Use `FetchMessage` and commit only after processing succeeds. On a read error,
log it and retry with a delay that respects the application context. Keep using
the same `reader`; it manages its partition connection and resumes reading:

The snippet assumes `reader` is configured as above, `ctx` is the application's
context, and `process` handles one message. Add the `fmt`, `log`, and `time`
imports.

```go
for {
	msg, err := reader.FetchMessage(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("fetch failed; retrying: %v", err)

		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		continue
	}

	if err := process(ctx, msg); err != nil {
		return fmt.Errorf("process message: %w", err)
	}
	if err := reader.CommitMessages(ctx, msg); err != nil {
		return fmt.Errorf("commit message: %w", err)
	}
}
```

This loop handles errors reported to the application while the reader keeps
trying to establish its partition connection. It does not renew the token on
the connection that failed. `process` and `CommitMessages` need their own error
policy. A processing or commit retry can result in the same message being
processed again, so make processing idempotent if duplicate delivery is not
acceptable.

### Publisher

If `WriteMessages` fails after its internal retries, retry with a bounded
application policy using the same long-lived writer, and surface or persist the
final failure. Kafka may have accepted a message even when the client did not
receive a successful response, so retrying can publish a duplicate. Use a
stable event ID and make consumers idempotent if retries are enabled:

The snippet assumes `writer` and `ctx` are configured, and `eventID` and
`payload` contain the event to publish. Add the `fmt`, `log`, and `time`
imports.

```go
msg := kafka.Message{
	Key:   []byte(eventID), // stable ID; consumers can use it for deduplication
	Value: payload,
}

var err error
for attempt := 1; attempt <= 3; attempt++ {
	err = writer.WriteMessages(ctx, msg)
	if err == nil {
		break
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}

	log.Printf("publish attempt %d failed: %v", attempt, err)
	if attempt == 3 {
		return fmt.Errorf("publish event %s: %w", eventID, err)
	}

	timer := time.NewTimer(time.Duration(attempt) * time.Second)
	select {
	case <-ctx.Done():
		timer.Stop()
		return ctx.Err()
	case <-timer.C:
	}
}
return nil
```

Use the same message ID for every retry. A Kafka message key alone does not
deduplicate records; the consumer must implement deduplication, or the
application must use another delivery strategy appropriate to its guarantees.

## Tests

Tests use an in-process token endpoint and do not require Kafka or an identity
provider:

```bash
go test -race -cover ./...
```
