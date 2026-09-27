package kerberos

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/require"
)

// krb5OIDBytes is the DER encoding of the Kerberos 5 GSS-API OID
// (1.2.840.113554.1.2.2) as emitted by asn1.Marshal.
var krb5OIDBytes = []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02}

func testSessionKey() types.EncryptionKey {
	return types.EncryptionKey{
		KeyType:  etypeID.AES128_CTS_HMAC_SHA1_96,
		KeyValue: []byte("0123456789abcdef"),
	}
}

func newTestSession() *session {
	return &session{
		ticket: messages.Ticket{
			TktVNO: 5,
			Realm:  "TEST.COM",
			SName:  types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "kafka/broker1"),
			EncPart: types.EncryptedData{
				EType:  etypeID.AES128_CTS_HMAC_SHA1_96,
				KVNO:   1,
				Cipher: []byte("cipher-bytes"),
			},
		},
		encKey: testSessionKey(),
		domain: "TEST.COM",
		cname:  types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user"),
		step:   stepInitial,
	}
}

// buildAcceptorWrapToken crafts a GSS-API wrap token as it would be emitted by
// the service acceptor during the verification step.
func buildAcceptorWrapToken(t *testing.T, key types.EncryptionKey, payload []byte) []byte {
	t.Helper()
	et, err := crypto.GetEtype(key.KeyType)
	require.NoError(t, err)
	wt := &gssapi.WrapToken{
		Flags:   0x01, // fromAcceptor.
		EC:      uint16(et.GetHMACBitLength() / 8),
		Payload: payload,
	}
	require.NoError(t, wt.SetCheckSum(key, keyusage.GSSAPI_ACCEPTOR_SEAL))
	b, err := wt.Marshal()
	require.NoError(t, err)
	return b
}

func TestMechanism_spn(t *testing.T) {
	t.Run("default format", func(t *testing.T) {
		m := &Mechanism{Config: Config{ServiceName: "kafka"}}
		require.Equal(t, "kafka/broker1", m.spn("broker1"))
	})

	t.Run("custom BuildSpn", func(t *testing.T) {
		m := &Mechanism{Config: Config{
			ServiceName: "kafka",
			BuildSpn:    func(serviceName, host string) string { return serviceName + "@" + host },
		}}
		require.Equal(t, "kafka@broker1", m.spn("broker1"))
	})
}

func TestSession_Next_InvalidStep(t *testing.T) {
	s := &session{step: 42}
	_, resp, err := s.Next(context.Background(), nil)
	require.Nil(t, resp)
	require.ErrorContains(t, err, "unexpected kerberos step 42")
}

func TestSession_Next_Finish(t *testing.T) {
	s := &session{step: stepFinish}
	done, resp, err := s.Next(context.Background(), nil)
	require.True(t, done)
	require.Nil(t, resp)
	require.NoError(t, err)
}

func TestSession_Next_VerifyError(t *testing.T) {
	s := newTestSession()
	s.step = stepVerify
	done, resp, err := s.Next(context.Background(), []byte{0x00})
	require.False(t, done)
	require.Nil(t, resp)
	require.Error(t, err)
}

func TestSession_initSecContext_Initial(t *testing.T) {
	s := newTestSession()
	token, err := s.initSecContext(nil)
	require.NoError(t, err)
	require.Equal(t, stepVerify, s.step)

	// GSS-API header: application tag followed by the Kerberos OID, then the
	// AP-REQ token id 0x0100.
	require.Equal(t, byte(gssAPIGenericTag), token[0])
	idx := bytes.Index(token, krb5OIDBytes)
	require.Greater(t, idx, 1, "kerberos OID not found in token")
	rest := token[idx+len(krb5OIDBytes):]
	require.GreaterOrEqual(t, len(rest), 2)
	require.Equal(t, byte(0x01), rest[0])
	require.Equal(t, byte(0x00), rest[1])
}

func TestSession_initSecContext_InitialBadKey(t *testing.T) {
	s := newTestSession()
	s.encKey.KeyType = 999 // unsupported etype.
	_, err := s.initSecContext(nil)
	require.Error(t, err)
	require.Equal(t, stepInitial, s.step)
}

func TestSession_initSecContext_AuthenticatorError(t *testing.T) {
	original := newAuthenticator
	defer func() { newAuthenticator = original }()
	newAuthenticator = func(string, types.PrincipalName) (types.Authenticator, error) {
		return types.Authenticator{}, errors.New("injected authenticator error")
	}
	s := newTestSession()
	_, err := s.initSecContext(nil)
	require.ErrorContains(t, err, "injected authenticator error")
}

func TestSession_initSecContext_MarshalAPReqError(t *testing.T) {
	original := marshalAPReq
	defer func() { marshalAPReq = original }()
	marshalAPReq = func(*messages.APReq) ([]byte, error) {
		return nil, errors.New("injected marshal error")
	}
	s := newTestSession()
	_, err := s.initSecContext(nil)
	require.ErrorContains(t, err, "injected marshal error")
}

func TestSession_initSecContext_Verify(t *testing.T) {
	s := newTestSession()
	_, err := s.initSecContext(nil)
	require.NoError(t, err)

	payload := []byte("challenge from the service")
	challenge := buildAcceptorWrapToken(t, s.encKey, payload)

	resp, err := s.initSecContext(challenge)
	require.NoError(t, err)
	require.Equal(t, stepFinish, s.step)

	var rt gssapi.WrapToken
	require.NoError(t, rt.Unmarshal(resp, false))
	ok, err := rt.Verify(s.encKey, keyusage.GSSAPI_INITIATOR_SEAL)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, payload, rt.Payload)
}

func TestSession_initSecContext_VerifyBadChecksum(t *testing.T) {
	s := newTestSession()
	s.step = stepVerify
	challenge := buildAcceptorWrapToken(t, s.encKey, []byte("challenge"))
	challenge[len(challenge)-1] ^= 0xFF // corrupt the checksum.
	_, err := s.initSecContext(challenge)
	require.ErrorContains(t, err, "wrap token verify failed")
}

func TestSession_initSecContext_VerifyBadToken(t *testing.T) {
	s := newTestSession()
	s.step = stepVerify
	_, err := s.initSecContext([]byte{0x00, 0x01})
	require.Error(t, err)
}

func TestSession_initSecContext_UnknownStep(t *testing.T) {
	s := &session{step: stepFinish}
	token, err := s.initSecContext(nil)
	require.NoError(t, err)
	require.Nil(t, token)
}

func TestSession_initSecContext_WrapTokenError(t *testing.T) {
	original := newInitiatorWrapToken
	defer func() { newInitiatorWrapToken = original }()
	newInitiatorWrapToken = func([]byte, types.EncryptionKey) (*gssapi.WrapToken, error) {
		return nil, errors.New("injected wrap token error")
	}
	s := newTestSession()
	s.step = stepVerify
	challenge := buildAcceptorWrapToken(t, s.encKey, []byte("challenge"))
	_, err := s.initSecContext(challenge)
	require.ErrorContains(t, err, "injected wrap token error")
}

func TestSession_FullHandshake(t *testing.T) {
	s := newTestSession()

	token, err := s.initSecContext(nil)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	challenge := buildAcceptorWrapToken(t, s.encKey, []byte("challenge"))
	done, resp, err := s.Next(context.Background(), challenge)
	require.NoError(t, err)
	require.False(t, done)
	require.NotEmpty(t, resp)

	done, resp, err = s.Next(context.Background(), nil)
	require.NoError(t, err)
	require.True(t, done)
	require.Nil(t, resp)
}

func TestSession_appendGSSAPIHeader(t *testing.T) {
	s := &session{}
	out, err := s.appendGSSAPIHeader([]byte{0x01, 0x00, 'A', 'B'})
	require.NoError(t, err)
	expected := append([]byte{gssAPIGenericTag, 0x0F}, krb5OIDBytes...)
	expected = append(expected, 0x01, 0x00, 'A', 'B')
	require.Equal(t, expected, out)
}

func TestSession_appendGSSAPIHeader_MarshalError(t *testing.T) {
	original := asn1Marshal
	defer func() { asn1Marshal = original }()
	asn1Marshal = func(interface{}) ([]byte, error) {
		return nil, errors.New("injected marshal error")
	}
	s := &session{}
	_, err := s.appendGSSAPIHeader([]byte{0x01})
	require.ErrorContains(t, err, "injected marshal error")
}

func TestNewAuthenticatorChecksum(t *testing.T) {
	cs := newAuthenticatorChecksum()
	require.Len(t, cs, 24)
	// First four bytes hold the channel binding length (16) in little-endian.
	require.Equal(t, uint32(16), binary.LittleEndian.Uint32(cs[:4]))
	// Bytes 20-24 hold the GSS-API context flags in little-endian.
	flags := binary.LittleEndian.Uint32(cs[20:24])
	require.Equal(t, uint32(gssapi.ContextFlagInteg|gssapi.ContextFlagConf), flags)
}
