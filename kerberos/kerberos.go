package kerberos

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/segmentio/kafka-go/sasl"
)

// AuthType selects how the Kerberos client obtains credentials.
type AuthType int

const (
	// KRB5_USER_AUTH obtains credentials from username and password.
	KRB5_USER_AUTH AuthType = iota + 1
	// KRB5_KEYTAB_AUTH obtains credentials from a keytab file.
	KRB5_KEYTAB_AUTH
	// KRB5_CCACHE_AUTH obtains credentials from a credential cache file.
	KRB5_CCACHE_AUTH
)

const (
	tokIDKrbApReq    = 256
	gssAPIGenericTag = 0x60

	stepInitial = iota
	stepVerify
	stepFinish
)

// Config holds parameters for Kerberos/GSSAPI SASL authentication.
type Config struct {
	// AuthType selects the credential source.
	AuthType AuthType

	// KeyTabPath is the path to a keytab file. Required when AuthType is KRB5_KEYTAB_AUTH.
	KeyTabPath string

	// CCachePath is the path to a credentials cache. Required when AuthType is KRB5_CCACHE_AUTH.
	CCachePath string

	// KerberosConfigPath is the path to krb5.conf. Required.
	KerberosConfigPath string

	// ServiceName is the Kerberos service name (e.g., "kafka"). Required.
	ServiceName string

	// Username is the Kerberos principal name without the realm.
	// Required for user and keytab auth.
	Username string

	// Password is the password. Required for user auth.
	Password string

	// Realm is the Kerberos realm. Required for user and keytab auth.
	Realm string

	// DisablePAFXFAST disables the use of PA-FX-FAST.
	DisablePAFXFAST bool

	// BuildSpn constructs the SPN from the service name and host.
	// If nil, the default format "serviceName/host" is used.
	BuildSpn func(serviceName, host string) string
}

// Mechanism implements sasl.Mechanism for GSSAPI (Kerberos).
type Mechanism struct {
	Config Config
}

// Name returns "GSSAPI".
func (Mechanism) Name() string {
	return "GSSAPI"
}

// Start begins the SASL authentication and returns the initial AP-REQ token.
func (m *Mechanism) Start(ctx context.Context) (sasl.StateMachine, []byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("kerberos authentication canceled: %w", err)
	}
	if m.Config.AuthType < KRB5_USER_AUTH || m.Config.AuthType > KRB5_CCACHE_AUTH {
		return nil, nil, fmt.Errorf("unsupported kerberos auth type %d", m.Config.AuthType)
	}

	meta := sasl.MetadataFromContext(ctx)

	host := ""
	if meta != nil {
		host = meta.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}

	krb5Conf, err := config.Load(m.Config.KerberosConfigPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load krb5 config: %w", err)
	}

	var krbClient *client.Client
	switch m.Config.AuthType {
	case KRB5_KEYTAB_AUTH:
		kt, err := keytab.Load(m.Config.KeyTabPath)
		if err != nil {
			return nil, nil, fmt.Errorf("load keytab: %w", err)
		}
		if m.Config.Username == "" || m.Config.Realm == "" {
			return nil, nil, fmt.Errorf("username and realm required for keytab auth")
		}
		krbClient = client.NewWithKeytab(m.Config.Username, m.Config.Realm, kt, krb5Conf,
			client.DisablePAFXFAST(m.Config.DisablePAFXFAST))
	case KRB5_CCACHE_AUTH:
		cc, err := credentials.LoadCCache(m.Config.CCachePath)
		if err != nil {
			return nil, nil, fmt.Errorf("load credential cache: %w", err)
		}
		krbClient, err = client.NewFromCCache(cc, krb5Conf,
			client.DisablePAFXFAST(m.Config.DisablePAFXFAST))
		if err != nil {
			return nil, nil, fmt.Errorf("create client from ccache: %w", err)
		}
	default: // KRB5_USER_AUTH
		if m.Config.Username == "" || m.Config.Realm == "" {
			return nil, nil, fmt.Errorf("username and realm required for user auth")
		}
		krbClient = client.NewWithPassword(m.Config.Username, m.Config.Realm, m.Config.Password, krb5Conf,
			client.DisablePAFXFAST(m.Config.DisablePAFXFAST))
	}

	if err := krbClient.Login(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, fmt.Errorf("kerberos login canceled: %w", ctxErr)
		}
		return nil, nil, fmt.Errorf("kerberos login: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("kerberos login canceled: %w", err)
	}

	spn := m.spn(host)
	ticket, encKey, err := krbClient.GetServiceTicket(spn)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, fmt.Errorf("get service ticket canceled: %w", ctxErr)
		}
		return nil, nil, fmt.Errorf("get service ticket for %s: %w", spn, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, fmt.Errorf("get service ticket canceled: %w", err)
	}

	sess := &session{
		client: krbClient,
		ticket: ticket,
		encKey: encKey,
		domain: krbClient.Credentials.Domain(),
		cname:  krbClient.Credentials.CName(),
		step:   stepInitial,
	}

	token, err := sess.initSecContext(nil)
	if err != nil {
		return nil, nil, err
	}
	return sess, token, nil
}

func (m *Mechanism) spn(host string) string {
	if m.Config.BuildSpn != nil {
		return m.Config.BuildSpn(m.Config.ServiceName, host)
	}
	return fmt.Sprintf("%s/%s", m.Config.ServiceName, host)
}

type session struct {
	client *client.Client
	ticket messages.Ticket
	encKey types.EncryptionKey
	domain string
	cname  types.PrincipalName
	step   int
}

func (s *session) Next(ctx context.Context, challenge []byte) (bool, []byte, error) {
	switch s.step {
	case stepVerify:
		token, err := s.initSecContext(challenge)
		if err != nil {
			return false, nil, err
		}
		return false, token, nil
	case stepFinish:
		return true, nil, nil
	default:
		return true, nil, fmt.Errorf("unexpected kerberos step %d", s.step)
	}
}

// Indirections that let tests inject failures into error paths that are
// otherwise unreachable (randomness, marshaling of fixed structures).
var (
	newAuthenticator      = types.NewAuthenticator
	marshalAPReq          = func(apReq *messages.APReq) ([]byte, error) { return apReq.Marshal() }
	newInitiatorWrapToken = gssapi.NewInitiatorWrapToken
	asn1Marshal           = asn1.Marshal
)

func (s *session) initSecContext(challenge []byte) ([]byte, error) {
	switch s.step {
	case stepInitial:
		auth, err := newAuthenticator(s.domain, s.cname)
		if err != nil {
			return nil, err
		}
		auth.Cksum = types.Checksum{
			CksumType: chksumtype.GSSAPI,
			Checksum:  newAuthenticatorChecksum(),
		}
		apReq, err := messages.NewAPReq(s.ticket, s.encKey, auth)
		if err != nil {
			return nil, err
		}
		aprBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(aprBytes, uint16(tokIDKrbApReq))
		tb, err := marshalAPReq(&apReq)
		if err != nil {
			return nil, err
		}
		aprBytes = append(aprBytes, tb...)
		s.step = stepVerify
		return s.appendGSSAPIHeader(aprBytes)
	case stepVerify:
		wrapTokenReq := gssapi.WrapToken{}
		if err := wrapTokenReq.Unmarshal(challenge, true); err != nil {
			return nil, err
		}
		valid, err := wrapTokenReq.Verify(s.encKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if !valid {
			return nil, fmt.Errorf("wrap token verify failed: %w", err)
		}
		wrapTokenResponse, err := newInitiatorWrapToken(wrapTokenReq.Payload, s.encKey)
		if err != nil {
			return nil, err
		}
		s.step = stepFinish
		return wrapTokenResponse.Marshal()
	}
	return nil, nil
}

func (s *session) appendGSSAPIHeader(payload []byte) ([]byte, error) {
	oidBytes, err := asn1Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		return nil, err
	}
	tkoLengthBytes := asn1tools.MarshalLengthBytes(len(oidBytes) + len(payload))
	gssHeader := append([]byte{gssAPIGenericTag}, tkoLengthBytes...)
	gssHeader = append(gssHeader, oidBytes...)
	return append(gssHeader, payload...), nil
}

func newAuthenticatorChecksum() []byte {
	a := make([]byte, 24)
	binary.LittleEndian.PutUint32(a[:4], 16)
	flags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}
	for _, i := range flags {
		f := binary.LittleEndian.Uint32(a[20:24])
		f |= uint32(i)
		binary.LittleEndian.PutUint32(a[20:24], f)
	}
	return a
}
