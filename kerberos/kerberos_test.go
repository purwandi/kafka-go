package kerberos_test

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/purwandi/kafka-go/kerberos"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/stretchr/testify/require"
)

// testKrb5Conf points the TEST.COM realm at an unreachable KDC so login and
// ticket exchanges fail fast with connection refused instead of DNS timeouts.
const testKrb5Conf = `
[libdefaults]
	default_realm = TEST.COM
	dns_lookup_kdc = false
	dns_lookup_realm = false

[realms]
	TEST.COM = {
		kdc = 127.0.0.1:1
	}
`

func writeTempFile(t *testing.T, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	require.NoError(t, os.WriteFile(path, data, 0o600))
	return path
}

func writeTempKrb5Conf(t *testing.T) string {
	t.Helper()
	return writeTempFile(t, "krb5.conf", []byte(testKrb5Conf))
}

func writeTempKeytab(t *testing.T) string {
	t.Helper()
	kt := keytab.New()
	require.NoError(t, kt.AddEntry("user", "TEST.COM", "password", time.Now(), 1, etypeID.AES128_CTS_HMAC_SHA1_96))
	b, err := kt.Marshal()
	require.NoError(t, err)
	return writeTempFile(t, "client.keytab", b)
}

func ccacheInt16(b []byte, v int32) []byte {
	var x [2]byte
	binary.BigEndian.PutUint16(x[:], uint16(v))
	return append(b, x[:]...)
}

func ccacheInt32(b []byte, v int32) []byte {
	var x [4]byte
	binary.BigEndian.PutUint32(x[:], uint32(v))
	return append(b, x[:]...)
}

func ccacheData(b []byte, data []byte) []byte {
	b = ccacheInt32(b, int32(len(data)))
	return append(b, data...)
}

func ccachePrincipal(b []byte, realm string, components ...string) []byte {
	b = ccacheInt32(b, nametype.KRB_NT_PRINCIPAL)
	b = ccacheInt32(b, int32(len(components)))
	b = ccacheData(b, []byte(realm))
	for _, c := range components {
		b = ccacheData(b, []byte(c))
	}
	return b
}

// buildCCache builds a minimal version 4 credential cache for user@TEST.COM.
// When withTGT is false the cache contains no credentials, which exercises the
// "TGT not found in CCache" error path of client.NewFromCCache.
func buildCCache(t *testing.T, withTGT bool) []byte {
	t.Helper()
	b := []byte{0x05, 0x04, 0x00, 0x00} // magic 5, version 4, zero-length header.
	b = ccachePrincipal(b, "TEST.COM", "user")
	if withTGT {
		b = ccacheCredential(t, b, "krbtgt/TEST.COM", etypeID.AES128_CTS_HMAC_SHA1_96, make([]byte, 16), time.Now())
	}
	return b
}

// buildCCacheWithService builds a ccache holding both a TGT and a cached
// service ticket for the given SPN, so Start can complete without a KDC.
func buildCCacheWithService(t *testing.T, spn string, keyType int32, keyValue []byte) []byte {
	t.Helper()
	b := buildCCache(t, true)
	return ccacheCredential(t, b, spn, keyType, keyValue, time.Now())
}

// ccacheCredential appends a credential for sname (e.g. "krbtgt/TEST.COM")
// issued to user@TEST.COM, valid from one minute ago for one hour.
func ccacheCredential(t *testing.T, b []byte, sname string, keyType int32, keyValue []byte, now time.Time) []byte {
	t.Helper()
	tkt := messages.Ticket{
		TktVNO: 5,
		Realm:  "TEST.COM",
		SName:  types.NewPrincipalName(nametype.KRB_NT_SRV_INST, sname),
		EncPart: types.EncryptedData{
			EType:  etypeID.AES128_CTS_HMAC_SHA1_96,
			KVNO:   1,
			Cipher: []byte("cipher-bytes"),
		},
	}
	tb, err := tkt.Marshal()
	require.NoError(t, err)

	b = ccachePrincipal(b, "TEST.COM", "user")                       // client principal.
	b = ccachePrincipal(b, "TEST.COM", strings.Split(sname, "/")...) // server principal.
	b = ccacheInt16(b, keyType)                                      // key type.
	b = ccacheData(b, keyValue)                                      // key value.
	b = ccacheInt32(b, int32(now.Add(-time.Minute).Unix()))          // auth time.
	b = ccacheInt32(b, int32(now.Add(-time.Minute).Unix()))          // start time.
	b = ccacheInt32(b, int32(now.Add(time.Hour).Unix()))             // end time.
	b = ccacheInt32(b, int32(now.Add(time.Hour).Unix()))             // renew till.
	b = append(b, 0)                                                 // is_skey.
	b = append(b, 0, 0, 0, 0)                                        // ticket flags.
	b = ccacheInt32(b, 0)                                            // addresses count.
	b = ccacheInt32(b, 0)                                            // auth data count.
	b = ccacheData(b, tb)                                            // ticket.
	b = ccacheData(b, nil)                                           // second ticket.
	return b
}

func TestMechanism_Name(t *testing.T) {
	m := &kerberos.Mechanism{Config: kerberos.Config{}}
	require.Equal(t, "GSSAPI", m.Name())
}

func TestMechanism_Start_LoadConfigError(t *testing.T) {
	m := &kerberos.Mechanism{Config: kerberos.Config{}}
	sess, token, err := m.Start(context.Background())
	require.Nil(t, sess)
	require.Nil(t, token)
	require.ErrorContains(t, err, "load krb5 config")
}

func TestMechanism_Start_MetadataHost(t *testing.T) {
	configPath := writeTempKrb5Conf(t)

	for _, tt := range []struct {
		name string
		host string
	}{
		{name: "host with port", host: "broker1:9093"},
		{name: "host without port", host: "broker1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := &kerberos.Mechanism{Config: kerberos.Config{
				AuthType:           kerberos.KRB5_USER_AUTH,
				KerberosConfigPath: configPath,
				ServiceName:        "kafka",
				// Missing username and realm forces an error after metadata
				// parsing, keeping the test offline.
			}}
			ctx := sasl.WithMetadata(context.Background(), &sasl.Metadata{Host: tt.host})
			_, _, err := m.Start(ctx)
			require.ErrorContains(t, err, "username and realm required for user auth")
		})
	}
}

func TestMechanism_Start_UserAuth(t *testing.T) {
	configPath := writeTempKrb5Conf(t)

	t.Run("missing username and realm", func(t *testing.T) {
		m := &kerberos.Mechanism{Config: kerberos.Config{
			AuthType:           kerberos.KRB5_USER_AUTH,
			KerberosConfigPath: configPath,
			ServiceName:        "kafka",
		}}
		_, _, err := m.Start(context.Background())
		require.ErrorContains(t, err, "username and realm required for user auth")
	})

	t.Run("login failure against unreachable kdc", func(t *testing.T) {
		m := &kerberos.Mechanism{Config: kerberos.Config{
			AuthType:           kerberos.KRB5_USER_AUTH,
			KerberosConfigPath: configPath,
			ServiceName:        "kafka",
			Username:           "user",
			Password:           "password",
			Realm:              "TEST.COM",
			DisablePAFXFAST:    true,
		}}
		sess, token, err := m.Start(context.Background())
		require.Nil(t, sess)
		require.Nil(t, token)
		require.ErrorContains(t, err, "kerberos login")
	})
}

func TestMechanism_Start_KeytabAuth(t *testing.T) {
	configPath := writeTempKrb5Conf(t)

	t.Run("missing keytab file", func(t *testing.T) {
		m := &kerberos.Mechanism{Config: kerberos.Config{
			AuthType:           kerberos.KRB5_KEYTAB_AUTH,
			KerberosConfigPath: configPath,
			KeyTabPath:         filepath.Join(t.TempDir(), "missing.keytab"),
			ServiceName:        "kafka",
		}}
		_, _, err := m.Start(context.Background())
		require.ErrorContains(t, err, "load keytab")
	})

	t.Run("missing username and realm", func(t *testing.T) {
		m := &kerberos.Mechanism{Config: kerberos.Config{
			AuthType:           kerberos.KRB5_KEYTAB_AUTH,
			KerberosConfigPath: configPath,
			KeyTabPath:         writeTempKeytab(t),
			ServiceName:        "kafka",
		}}
		_, _, err := m.Start(context.Background())
		require.ErrorContains(t, err, "username and realm required for keytab auth")
	})

	t.Run("login failure against unreachable kdc", func(t *testing.T) {
		m := &kerberos.Mechanism{Config: kerberos.Config{
			AuthType:           kerberos.KRB5_KEYTAB_AUTH,
			KerberosConfigPath: configPath,
			KeyTabPath:         writeTempKeytab(t),
			ServiceName:        "kafka",
			Username:           "user",
			Realm:              "TEST.COM",
			DisablePAFXFAST:    true,
		}}
		_, _, err := m.Start(context.Background())
		require.ErrorContains(t, err, "kerberos login")
	})
}

func TestMechanism_Start_CCacheAuth(t *testing.T) {
	configPath := writeTempKrb5Conf(t)

	t.Run("missing ccache file", func(t *testing.T) {
		m := &kerberos.Mechanism{Config: kerberos.Config{
			AuthType:           kerberos.KRB5_CCACHE_AUTH,
			KerberosConfigPath: configPath,
			CCachePath:         filepath.Join(t.TempDir(), "missing.ccache"),
			ServiceName:        "kafka",
		}}
		_, _, err := m.Start(context.Background())
		require.ErrorContains(t, err, "load credential cache")
	})

	t.Run("ccache without tgt", func(t *testing.T) {
		m := &kerberos.Mechanism{Config: kerberos.Config{
			AuthType:           kerberos.KRB5_CCACHE_AUTH,
			KerberosConfigPath: configPath,
			CCachePath:         writeTempFile(t, "client.ccache", buildCCache(t, false)),
			ServiceName:        "kafka",
		}}
		_, _, err := m.Start(context.Background())
		require.ErrorContains(t, err, "create client from ccache")
	})

	t.Run("service ticket failure against unreachable kdc", func(t *testing.T) {
		m := &kerberos.Mechanism{Config: kerberos.Config{
			AuthType:           kerberos.KRB5_CCACHE_AUTH,
			KerberosConfigPath: configPath,
			CCachePath:         writeTempFile(t, "client.ccache", buildCCache(t, true)),
			ServiceName:        "kafka",
			DisablePAFXFAST:    true,
		}}
		_, _, err := m.Start(context.Background())
		require.ErrorContains(t, err, "get service ticket for kafka/")
	})

	t.Run("successful start with cached service ticket", func(t *testing.T) {
		m := &kerberos.Mechanism{Config: kerberos.Config{
			AuthType:           kerberos.KRB5_CCACHE_AUTH,
			KerberosConfigPath: configPath,
			CCachePath:         writeTempFile(t, "client.ccache", buildCCacheWithService(t, "kafka/broker1", etypeID.AES128_CTS_HMAC_SHA1_96, make([]byte, 16))),
			ServiceName:        "kafka",
			DisablePAFXFAST:    true,
		}}
		ctx := sasl.WithMetadata(context.Background(), &sasl.Metadata{Host: "broker1:9093"})
		sess, token, err := m.Start(ctx)
		require.NoError(t, err)
		require.NotNil(t, sess)
		require.NotEmpty(t, token)
		require.Equal(t, byte(0x60), token[0])
	})

	t.Run("initial context failure with unsupported cached key", func(t *testing.T) {
		m := &kerberos.Mechanism{Config: kerberos.Config{
			AuthType:           kerberos.KRB5_CCACHE_AUTH,
			KerberosConfigPath: configPath,
			CCachePath:         writeTempFile(t, "client.ccache", buildCCacheWithService(t, "kafka/broker1", 999, make([]byte, 16))),
			ServiceName:        "kafka",
			DisablePAFXFAST:    true,
		}}
		ctx := sasl.WithMetadata(context.Background(), &sasl.Metadata{Host: "broker1:9093"})
		sess, token, err := m.Start(ctx)
		require.Nil(t, sess)
		require.Nil(t, token)
		require.ErrorContains(t, err, "unknown or unsupported EType: 999")
	})
}
