# sasl/kerberos

Kerberos (GSSAPI) SASL authentication for
[`kafka-go`](https://github.com/segmentio/kafka-go). Use it as the
`SASLMechanism` of a `kafka.Dialer` (readers and low-level connections) or as
the `SASL` mechanism of a `kafka.Transport` (writers).

## Configure a reader

Configure the broker principal as `kafka/<broker-host>@<REALM>`, and ensure
the application can read `krb5.conf` and reach the KDC.

```go
package main

import (
	"crypto/tls"
	"time"

	"github.com/purwandi/kafka-go/kerberos"
	"github.com/segmentio/kafka-go"
)

func main() {
	mechanism := &kerberos.Mechanism{
		Config: kerberos.Config{
			AuthType:           kerberos.KRB5_USER_AUTH,
			KerberosConfigPath: "/etc/krb5.conf",
			ServiceName:        "kafka",
			Username:           "alice",
			Password:           "read-from-a-secret-store",
			Realm:              "EXAMPLE.COM",
		},
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: []string{"broker1.example.com:9093"},
		GroupID: "consumer-group",
		Topic:   "events",
		Dialer: &kafka.Dialer{
			Timeout:       10 * time.Second,
			DualStack:     true,
			SASLMechanism: mechanism,
			TLS:           &tls.Config{},
		},
	})
	defer reader.Close()
}
```

Kerberos authenticates the connection but does not encrypt Kafka traffic. Use
TLS when traffic encryption is required. Read credentials from an environment
variable or secret store rather than hard-coding them.

## Configure a writer

Pass the mechanism through a `kafka.Transport`:

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

## Authentication types

`Config.AuthType` selects where the client obtains Kerberos credentials. All
types require `KerberosConfigPath` (path to `krb5.conf`) and `ServiceName`
(usually `kafka`).

### `KRB5_USER_AUTH` — username and password

Requires `Username`, `Password`, and `Realm`. The credentials are used to
authenticate with the KDC.

```go
kerberos.Config{
	AuthType:           kerberos.KRB5_USER_AUTH,
	KerberosConfigPath: "/etc/krb5.conf",
	ServiceName:        "kafka",
	Username:           "alice",
	Password:           os.Getenv("KRB5_PASSWORD"),
	Realm:              "EXAMPLE.COM",
}
```

### `KRB5_KEYTAB_AUTH` — keytab

Requires `KeyTabPath`, `Username`, and `Realm`. The keytab supplies the
credential; a password is not needed.

```go
kerberos.Config{
	AuthType:           kerberos.KRB5_KEYTAB_AUTH,
	KerberosConfigPath: "/etc/krb5.conf",
	KeyTabPath:         "/opt/myapp/myapp.keytab",
	ServiceName:        "kafka",
	Username:           "myapp",
	Realm:              "EXAMPLE.COM",
}
```

Create a keytab with `ktutil` or ask your Kerberos administrator:

```text
ktutil: addent -password -p myapp@EXAMPLE.COM -k 1 -e aes256-cts-hmac-sha1-96
ktutil: wkt /opt/myapp/myapp.keytab
ktutil: quit
```

### `KRB5_CCACHE_AUTH` — credential cache

Requires `CCachePath`. The principal and realm are read from the cache. For
example, create a cache with `kinit`:

```bash
kinit alice@EXAMPLE.COM
# Or specify a cache file:
kinit -c /tmp/myapp.ccache alice@EXAMPLE.COM
```

Set `CCachePath` to the cache file, for example `/tmp/myapp.ccache`.

## Custom service principal name

The service principal name defaults to `serviceName/host`; the broker port is
removed from the host. Set `BuildSpn` if the broker uses a different format:

```go
BuildSpn: func(serviceName, host string) string {
	return serviceName + "/" + host + "@EXAMPLE.COM"
},
```

## Configuration reference

| Field                | Description                                                  |
|----------------------|--------------------------------------------------------------|
| `AuthType`           | `KRB5_USER_AUTH`, `KRB5_KEYTAB_AUTH`, or `KRB5_CCACHE_AUTH`. |
| `KerberosConfigPath` | Path to `krb5.conf`. Required.                               |
| `ServiceName`        | Broker service name, usually `kafka`. Required.              |
| `Username`           | Principal without realm. Required for user and keytab auth.  |
| `Password`           | Password. Required for user auth.                            |
| `Realm`              | Kerberos realm. Required for user and keytab auth.           |
| `KeyTabPath`         | Keytab path. Required for keytab auth.                       |
| `CCachePath`         | Credential-cache path. Required for ccache auth.             |
| `DisablePAFXFAST`    | Disable PA-FX-FAST negotiation.                              |
| `BuildSpn`           | Optional function to customize the service principal name.   |

## Tests

The package tests run offline and do not require a KDC:

```bash
go test -race -cover ./...
```
