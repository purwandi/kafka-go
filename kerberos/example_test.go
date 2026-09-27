package kerberos_test

import (
	"crypto/tls"
	"time"

	"github.com/purwandi/kafka-go/kerberos"
	"github.com/segmentio/kafka-go"
)

// ExampleMechanism_userPasswordAuth shows how to authenticate against a
// Kerberos-enabled Kafka cluster with a username and password.
func ExampleMechanism_userPasswordAuth() {
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
		TLS:           &tls.Config{}, // Kerberos does not encrypt payloads; use TLS.
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: []string{"broker1.example.com:9093"},
		GroupID: "consumer-group",
		Topic:   "events",
		Dialer:  dialer,
	})
	defer reader.Close()
}

// ExampleMechanism_keytabAuth shows how to authenticate with a keytab file,
// suitable for services that must not store passwords.
func ExampleMechanism_keytabAuth() {
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
}

// ExampleMechanism_credentialCacheAuth shows how to authenticate using an
// existing credential cache (e.g. one created by kinit on the host).
func ExampleMechanism_credentialCacheAuth() {
	mechanism := &kerberos.Mechanism{
		Config: kerberos.Config{
			AuthType:           kerberos.KRB5_CCACHE_AUTH,
			KerberosConfigPath: "/etc/krb5.conf",
			CCachePath:         "/tmp/krb5cc_1000",
			ServiceName:        "kafka",
		},
	}

	dialer := &kafka.Dialer{
		Timeout:       10 * time.Second,
		DualStack:     true,
		SASLMechanism: mechanism,
		TLS:           &tls.Config{},
	}

	reader := kafka.NewReader(kafka.ReaderConfig{
		Brokers: []string{"broker1.example.com:9093"},
		GroupID: "consumer-group",
		Topic:   "events",
		Dialer:  dialer,
	})
	defer reader.Close()
}

// ExampleConfig_BuildSpn shows how to override the SPN construction, for
// example when the broker principal does not follow the default
// "serviceName/host" convention.
func ExampleConfig_BuildSpn() {
	mechanism := &kerberos.Mechanism{
		Config: kerberos.Config{
			AuthType:           kerberos.KRB5_USER_AUTH,
			KerberosConfigPath: "/etc/krb5.conf",
			ServiceName:        "kafka",
			Username:           "alice",
			Password:           "s3cret",
			Realm:              "EXAMPLE.COM",
			BuildSpn: func(serviceName, host string) string {
				return serviceName + "/" + host + "@EXAMPLE.COM"
			},
		},
	}

	_ = &kafka.Dialer{
		Timeout:       10 * time.Second,
		DualStack:     true,
		SASLMechanism: mechanism,
	}
}
