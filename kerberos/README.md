# sasl/kerberos

Kerberos (GSSAPI) SASL authentication for
[`kafka-go`](https://github.com/segmentio/kafka-go). Use it as the
`SASLMechanism` of a `kafka.Dialer` (readers, low-level connections) or as the
`SASL` mechanism of a `kafka.Transport` (writers) when connecting to a broker
configured with `GSSAPI`.

```bash
go get github.com/segmentio/kafka-go/sasl/kerberos
```

## Quick start

```go
mechanism := &kerberos.Mechanism{
	Config: kerberos.Config{
		AuthType:           kerberos.KRB5_USER_AUTH,
		KerberosConfigPath: "/etc/krb5.conf",
		ServiceName:        "kafka",
		Username:           "alice",
		Password:           "s3cret",
		Realm:              "EXAMPLE.COM",
	},
}

dialer := &kafka.Dialer{
	Timeout:       10 * time.Second,
	DualStack:     true,
	SASLMechanism: mechanism,
	TLS:           &tls.Config{}, // GSSAPI does not encrypt traffic; enable TLS.
}

reader := kafka.NewReader(kafka.ReaderConfig{
	Brokers: []string{"broker1.example.com:9093"},
	GroupID: "consumer-group",
	Topic:   "events",
	Dialer:  dialer,
})
```

For writers, pass the mechanism through a `kafka.Transport`:

```go
writer := &kafka.Writer{
	Addr:  kafka.TCP("broker1.example.com:9093"),
	Topic: "events",
	Transport: &kafka.Transport{
		SASL: mechanism,
		TLS:  &tls.Config{},
	},
}
```

## Authentication types

`Config.AuthType` selects where the client obtains its Kerberos credentials.
All types require `KerberosConfigPath` (path to `krb5.conf`) and `ServiceName`
(usually `kafka`, matching the broker's principal prefix).

### `KRB5_USER_AUTH` — username + password

Credentials are obtained from the KDC using a password. Requires `Username`,
`Password` and `Realm`.

```go
mechanism := &kerberos.Mechanism{
	Config: kerberos.Config{
		AuthType:           kerberos.KRB5_USER_AUTH,
		KerberosConfigPath: "/etc/krb5.conf",
		ServiceName:        "kafka",
		Username:           "alice",
		Password:           "s3cret",
		Realm:              "EXAMPLE.COM",
	},
}

dialer := &kafka.Dialer{
	Timeout:       10 * time.Second,
	DualStack:     true,
	SASLMechanism: mechanism,
	TLS:           &tls.Config{},
}

conn, err := dialer.DialContext(ctx, "tcp", "broker1.example.com:9093")
if err != nil {
	// handle error
}
defer conn.Close()
```

Prefer reading secrets from the environment or a secret store instead of
hard-coding:

```go
mechanism := &kerberos.Mechanism{
	Config: kerberos.Config{
		AuthType:           kerberos.KRB5_USER_AUTH,
		KerberosConfigPath: os.Getenv("KRB5_CONFIG"), // e.g. /etc/krb5.conf
		ServiceName:        "kafka",
		Username:           os.Getenv("KRB5_USERNAME"),
		Password:           os.Getenv("KRB5_PASSWORD"),
		Realm:              os.Getenv("KRB5_REALM"), // e.g. EXAMPLE.COM
	},
}
```

### `KRB5_KEYTAB_AUTH` — keytab file

Credentials are obtained from a keytab file. Preferred for long-running
services: no password stored in the configuration. Requires `KeyTabPath`,
`Username` and `Realm`. There is no password field; the key in the keytab acts
as the credential.

```go
mechanism := &kerberos.Mechanism{
	Config: kerberos.Config{
		AuthType:           kerberos.KRB5_KEYTAB_AUTH,
		KerberosConfigPath: "/etc/krb5.conf",
		KeyTabPath:         "/opt/myapp/myapp.keytab",
		ServiceName:        "kafka",
		Username:           "myapp",
		Realm:              "EXAMPLE.COM",
	},
}

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

err := writer.WriteMessages(ctx, kafka.Message{Value: []byte("hello")})
if err != nil {
	// handle error
}
```

Create a keytab with `ktutil` (or ask your Kerberos admin):

```bash
$ ktutil
ktutil:  addent -password -p myapp@EXAMPLE.COM -k 1 -e aes256-cts-hmac-sha1-96
ktutil:  wkt /opt/myapp/myapp.keytab
ktutil:  quit
```

### `KRB5_CCACHE_AUTH` — credential cache

Credentials are read from an existing cache file, e.g. one created by `kinit`
on the host (Linux default: `/tmp/krb5cc_<uid>`). Requires `CCachePath` only;
principal and realm come from the cache.

```go
mechanism := &kerberos.Mechanism{
	Config: kerberos.Config{
		AuthType:           kerberos.KRB5_CCACHE_AUTH,
		KerberosConfigPath: "/etc/krb5.conf",
		CCachePath:         "/tmp/krb5cc_1000",
		ServiceName:        "kafka",
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

for {
	msg, err := reader.ReadMessage(ctx)
	if err != nil {
		// handle error
		break
	}
	fmt.Printf("key=%s value=%s\n", msg.Key, msg.Value)
}
```

Populate the cache beforehand:

```bash
kinit alice@EXAMPLE.COM              # default cache, e.g. /tmp/krb5cc_1000
kinit -c /tmp/myapp.ccache alice@EXAMPLE.COM   # explicit cache path
```

## Config reference

| Field                | Description                                                        |
| -------------------- | ------------------------------------------------------------------ |
| `AuthType`           | `KRB5_USER_AUTH`, `KRB5_KEYTAB_AUTH` or `KRB5_CCACHE_AUTH`.        |
| `KerberosConfigPath` | Path to `krb5.conf`. Required.                                     |
| `ServiceName`        | Kerberos service name of the broker (e.g. `kafka`). Required.      |
| `Username`           | Principal without realm. Required for user and keytab auth.        |
| `Password`           | Required for user auth.                                            |
| `Realm`              | Kerberos realm. Required for user and keytab auth.                 |
| `KeyTabPath`         | Path to keytab file. Required for keytab auth.                     |
| `CCachePath`         | Path to credential cache. Required for ccache auth.                |
| `DisablePAFXFAST`    | Disable PA-FX-FAST negotiation; enable for very old KDCs.          |
| `BuildSpn`           | Optional custom SPN builder; default is `serviceName/host`.        |

## Custom SPN

The service principal name defaults to `serviceName/host`, where `host` is the
broker address (dial host, port stripped). Set `BuildSpn` when your principal
uses a different convention, e.g. an explicit realm suffix:

```go
BuildSpn: func(serviceName, host string) string {
	return serviceName + "/" + host + "@EXAMPLE.COM"
},
```

## Testing

The package tests are fully offline (no KDC required):

```bash
go test -race -cover ./...
```
