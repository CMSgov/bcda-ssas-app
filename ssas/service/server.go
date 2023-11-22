package service

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"gopkg.in/macaroon.v2"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/CMSgov/bcda-ssas-app/ssas/cfg"
	"github.com/go-chi/chi/v5"
	gcmw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v4"
	"github.com/pborman/uuid"
)

// Server configures and provisions an SSAS server
type Server struct {
	name string
	// port server is running on; must have leading :, as in ":3000"
	port string
	// version of code running this server
	version string
	// info contains json metadata about server
	info interface{}
	// router associates handlers to server endpoints
	router chi.Router
	// notSecure flag; when true, not running in https mode   // TODO set this from HTTP_ONLY envv
	notSecure bool
	//useMTLS flag; when true mtls will be used if notSecure is set to false, else it is ignored.
	useMTLS         bool
	tokenSigningKey *rsa.PrivateKey
	tokenTTL        time.Duration
	server          http.Server
	clientAssertAud string
}

// ChooseSigningKey will choose which signing key to use, either a file or an inline key.
// One or the other must be set, but not both.
func ChooseSigningKey(signingKeyPath, signingKey string) (*rsa.PrivateKey, error) {
	var key *rsa.PrivateKey = nil
	var error error = nil

	if signingKey == "" && signingKeyPath != "" {
		sk, err := GetPrivateKey(signingKeyPath)
		if err != nil {
			msg := fmt.Sprintf("bad signing key; path %s; %v", signingKeyPath, err)
			ssas.Logger.Error(msg)
			error = fmt.Errorf(msg)
		}
		key = sk
	} else if signingKey != "" && signingKeyPath == "" {
		sk, err := ssas.ReadPrivateKey([]byte(signingKey))
		if err != nil {
			msg := fmt.Sprintf("bad inline signing key; %v", err)
			ssas.Logger.Error(msg)
			error = fmt.Errorf(msg)
		}
		key = sk
	} else if signingKey == "" && signingKeyPath == "" {
		msg := "inline key and path are both empty strings"
		ssas.Logger.Error(msg)
		error = fmt.Errorf(msg)
	} else {
		msg := "inline key or path must be set, but not both"
		ssas.Logger.Error(msg)
		error = fmt.Errorf(msg)
	}

	return key, error
}

// NewServer correctly initializes an instance of the Server type.
func NewServer(name, port, version string, info interface{}, routes *chi.Mux, notSecure bool, useMTLS bool, signingKey *rsa.PrivateKey, ttl time.Duration, clientAssertAud string) *Server {

	if signingKey == nil {
		ssas.Logger.Error("Private Key is nil")
		return nil
	}

	err := signingKey.Validate()
	if err != nil {
		ssas.Logger.Error("Private Key is invalid")
		return nil
	}

	s := Server{}
	s.name = name
	s.port = port
	s.version = version
	s.info = info
	s.router = s.newBaseRouter()
	if routes != nil {
		s.router.Mount("/", routes)
	}
	s.notSecure = notSecure
	s.useMTLS = useMTLS
	s.tokenSigningKey = signingKey
	s.tokenTTL = ttl
	s.clientAssertAud = clientAssertAud
	s.server = http.Server{
		Handler:           s.router,
		Addr:              s.port,
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       time.Duration(cfg.GetEnvInt("SSAS_READ_TIMEOUT", 10)) * time.Second,
		WriteTimeout:      time.Duration(cfg.GetEnvInt("SSAS_WRITE_TIMEOUT", 20)) * time.Second,
		IdleTimeout:       time.Duration(cfg.GetEnvInt("SSAS_IDLE_TIMEOUT", 120)) * time.Second,
	}

	return &s
}

func BuildMTLSConfig() (*tls.Config, error) {
	caPool, cert, err := getServerCertificates()

	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		GetConfigForClient: func(hi *tls.ClientHelloInfo) (*tls.Config, error) {
			serverConf := &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    caPool,
			}
			return serverConf, nil
		},
	}, nil
}

func (s *Server) ListRoutes() ([]string, error) {
	var routes []string
	walker := func(method, route string, handler http.Handler, middlewares ...func(http.Handler) http.Handler) error {
		routes = append(routes, fmt.Sprintf("%s %s", method, route))
		return nil
	}
	err := chi.Walk(s.router, walker)
	return routes, err
}

// LogRoutes reports the routes supported by this server to the active log. Code is based on an example
// from https://itnext.io/structuring-a-production-grade-rest-api-in-golang-c0229b3feedc
func (s *Server) LogRoutes() {
	banner := fmt.Sprintf("Routes for %s at port %s: ", s.name, s.port)
	routes, err := s.ListRoutes()
	if err != nil {
		ssas.Logger.Infof("%s routing error: %v", banner, err)
		return
	}
	ssas.Logger.Infof("%s %v", banner, routes)
}

// Serve starts the server listening for and responding to requests.
func (s *Server) Serve() {
	if s.notSecure {
		ssas.Logger.Infof("starting %s server running UNSAFE http only mode; do not do this in production environments", s.name)
		go func() { log.Fatal(s.server.ListenAndServe()) }()
	} else {
		if s.useMTLS {
			conf, err := BuildMTLSConfig()
			if err != nil {
				log.Fatal(err)
			}
			s.server.TLSConfig = conf

			//If cert and key file paths are not passed the certs in TLS configs are used.
			ssas.Logger.Infof("starting %s server in MTLS mode", s.name)
			go func() { log.Fatal(s.server.ListenAndServeTLS("", "")) }()
		} else {
			tlsCertPath := os.Getenv("BCDA_TLS_CERT") // borrowing for now; we need to get our own (for both servers?)
			tlsKeyPath := os.Getenv("BCDA_TLS_KEY")
			ssas.Logger.Infof("starting %s server in TLS mode", s.name)
			go func() { log.Fatal(s.server.ListenAndServeTLS(tlsCertPath, tlsKeyPath)) }()
		}
	}
}

func getServerCertificates() (*x509.CertPool, tls.Certificate, error) {
	crtB, err := b64.StdEncoding.DecodeString(os.Getenv("BCDA_TLS_CERT_B64"))
	if err != nil {
		ssas.Logger.Error(err)
		return nil, tls.Certificate{}, errors.New("could not base64 decode BCDA_TLS_CERT_B64")
	}
	keyB, err := b64.StdEncoding.DecodeString(os.Getenv("BCDA_TLS_KEY_B64"))
	if err != nil {
		ssas.Logger.Error(err)
		return nil, tls.Certificate{}, errors.New("could not base64 decode BCDA_TLS_KEY_B64")
	}

	crtStr := string(crtB)
	keyStr := string(keyB)

	if crtStr == "" || keyStr == "" {
		ssas.Logger.Error(err)
		return nil, tls.Certificate{}, errors.New("one of the following required environment variables is missing or not base64 encoded: BCDA_TLS_CERT_B64, BCDA_TLS_KEY_B64")

	}

	// We are using the server cert as the CA cert.
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM([]byte(crtStr))
	if !ok {
		ssas.Logger.Error(err)
		return nil, tls.Certificate{}, errors.New("failed to parse server cert")
	}

	crt, err := tls.X509KeyPair([]byte(crtStr), []byte(keyStr))
	if err != nil {
		ssas.Logger.Error(err)
		return nil, tls.Certificate{}, errors.New("failed to parse server cert/key pair")
	}
	return certPool, crt, nil
}

// Stops the server listening for and responding to requests.
func (s *Server) Stop() {
	ssas.Logger.Infof("closing server %s; %+v", s.name, s.server.Close())
}

func (s *Server) newBaseRouter() *chi.Mux {
	r := chi.NewRouter()
	r.Use(
		gcmw.RequestID,
		NewAPILogger(),
		render.SetContentType(render.ContentTypeJSON),
		ConnectionClose,
	)
	r.Get("/_version", s.getVersion)
	r.Get("/_health", s.getHealthCheck)
	r.Get("/_info", s.getInfo)
	return r
}

func (s *Server) getInfo(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, s.info)
}

func (s *Server) getVersion(w http.ResponseWriter, r *http.Request) {
	respMap := make(map[string]string)
	respMap["version"] = fmt.Sprintf("%v", s.version)
	render.JSON(w, r, respMap)
}

func (s *Server) getHealthCheck(w http.ResponseWriter, r *http.Request) {
	m := make(map[string]string)
	if doHealthCheck(r.Context()) {
		m["database"] = "ok"
		w.WriteHeader(http.StatusOK)
	} else {
		m["database"] = "error"
		w.WriteHeader(http.StatusBadGateway)
	}
	render.JSON(w, r, m)
}

// is this the right health check for a service? the db could be up but the service down
// is there any condition under which the server could be running but become invalid?
// is there any circumstance where the server could be partially disabled? (e.g., unable to sign tokens but still running)
// could less than 3 servers be running?
// since this ping will be run against all servers, isn't this excessive?
func doHealthCheck(ctx context.Context) bool {
	db, err := ssas.Connection.WithContext(ctx).DB()
	if err != nil {
		// TODO health check failed event
		ssas.Logger.Error("health check: database connection error: ", err.Error())
		return false
	}

	if err = db.Ping(); err != nil {
		// (?) don't know if it actually gets to this error
		ssas.Logger.Error("health check: database ping error: ", err.Error())
		return false
	}

	return true
}

// This method gets the private key from the file system. Given that the server is completely unable to fulfill its
// purpose without a signing key, a server should be considered invalid if it this function returns an error.
func GetPrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	keyData, err := ssas.ReadPEMFile(keyPath)
	if err != nil {
		return nil, err
	}
	return ssas.ReadPrivateKey(keyData)
}

// NYI provides a convenience handler for endpoints that are not yet implemented
func NYI(w http.ResponseWriter, r *http.Request) {
	response := make(map[string]string)
	response["msg"] = "Not Yet Implemented"
	render.JSON(w, r, response)
}

// ConnectionClose provides a convenience handler for closing the http connection
func ConnectionClose(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		next.ServeHTTP(w, r)
	})
}

// GetFirstPartyCaveat extracts a first party caveat by name from macaroon
func GetFirstPartyCaveat(um macaroon.Macaroon, caveatName string) (string, error) {
	var caveatID string
	for _, v := range um.Caveats() {
		if strings.Contains(string(v.Id), caveatName) {
			caveatID = string(v.Id)
			break
		}
	}
	if caveatID == "" {
		return "", fmt.Errorf("missing %s in macaroon caveat", caveatName)
	}

	caveatIDKV := strings.Split(caveatID, "=")
	if len(caveatIDKV) != 2 {
		return "", fmt.Errorf("could not parse %s from macaroon caveats", caveatName)
	}
	return caveatIDKV[1], nil
}

// CommonClaims contains the superset of claims that may be found in the token
type CommonClaims struct {
	jwt.StandardClaims
	// AccessToken, MFAToken, ClientAssertion, or RegistrationToken
	TokenType string `json:"use,omitempty"`
	// In an MFA token, presence of an OktaID is taken as proof of username/password authentication
	OktaID   string `json:"oid,omitempty"`
	ClientID string `json:"cid,omitempty"`
	SystemID string `json:"sys,omitempty"`
	// In a registration token, GroupIDs contains a list of all groups this user is authorized to manage
	GroupIDs []string `json:"gid,omitempty"`
	Data     string   `json:"dat,omitempty"`
	Scopes   []string `json:"scp,omitempty"`
	// deprecated
	ACOID string `json:"aco,omitempty"`
	// deprecated
	UUID        string `json:"id,omitempty"`
	SystemXData string `json:"system_data,omitempty"`
}

// MintTokenWithDuration generates a tokenstring that expires after a specific duration from now.
// If duration is <= 0, the token will be expired upon creation
func (s *Server) MintTokenWithDuration(claims *CommonClaims, duration time.Duration) (*jwt.Token, string, error) {
	return s.mintToken(claims, time.Now().Unix(), time.Now().Add(duration).Unix())
}

// MintToken generates a tokenstring that expires in tokenTTL time
func (s *Server) MintToken(claims *CommonClaims) (*jwt.Token, string, error) {
	return s.mintToken(claims, time.Now().Unix(), time.Now().Add(s.tokenTTL).Unix())
}

func (s *Server) mintToken(claims *CommonClaims, issuedAt int64, expiresAt int64) (*jwt.Token, string, error) {
	token := jwt.New(jwt.SigningMethodRS512)
	tokenID := newTokenID()
	claims.IssuedAt = issuedAt
	claims.ExpiresAt = expiresAt
	claims.Id = tokenID
	claims.Issuer = "ssas"
	token.Claims = claims
	var signedString, err = token.SignedString(s.tokenSigningKey)
	if err != nil {
		ssas.TokenMintingFailure(ssas.Event{TokenID: tokenID})
		ssas.Logger.Errorf("token signing error %s", err)
		return nil, "", err
	}
	// not emitting AccessTokenIssued here because it hasn't been given to anyone
	return token, signedString, nil
}

func newTokenID() string {
	return uuid.NewRandom().String()
}

func (s *Server) VerifyToken(tokenString string) (*jwt.Token, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return &s.tokenSigningKey.PublicKey, nil
	}

	return jwt.ParseWithClaims(tokenString, &CommonClaims{}, keyFunc)
}

func (s *Server) VerifyClientSignedToken(ctx context.Context, tokenString string, trackingId string) (*jwt.Token, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		claims := token.Claims.(*CommonClaims)
		if claims.Issuer == "" {
			return nil, fmt.Errorf("missing issuer (iss) in jwt claims")
		}

		systemID, err := s.GetSystemIDFromMacaroon(claims.Issuer)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve systemID from macaroon")
		}

		system, err := ssas.GetSystemByID(ctx, systemID)
		if err != nil {
			ssas.Logger.Error(err)
			return nil, fmt.Errorf("failed to retrieve system information")
		}

		kid := token.Header["kid"]
		if kid == nil {
			return nil, fmt.Errorf("missing public key id (kid) in jwt header")
		}

		key, err := system.FindEncryptionKey(ctx, trackingId, kid.(string))
		if err != nil {
			ssas.Logger.Error(err)
			return nil, fmt.Errorf("key not found for system: %v", claims.Issuer)
		}
		pubKey, err := ssas.ReadPublicKey(key.Body)
		if err != nil {
			ssas.Logger.Error(err)
			return nil, fmt.Errorf("failed to read public key")

		}
		return pubKey, nil
	}
	return jwt.ParseWithClaims(tokenString, &CommonClaims{}, keyFunc)
}

// GetSystemIDFromMacaroon returns the system id from macaroon and verify macaroon
func (s *Server) GetSystemIDFromMacaroon(issuer string) (string, error) {
	db := ssas.Connection

	var um macaroon.Macaroon
	b, _ := base64.StdEncoding.DecodeString(issuer)
	_ = um.UnmarshalBinary(b)

	location := cfg.FromEnv("SSAS_MACAROON_LOCATION", "localhost")
	if um.Location() != location {
		return "", fmt.Errorf("location does not match expected %s", location)
	}

	systemId, err := GetFirstPartyCaveat(um, "system_id")
	if err != nil {
		return "", err
	}

	var rootKey ssas.RootKey
	db.First(&rootKey, "uuid = ? AND system_id = ? AND deleted_at IS NULL", um.Id(), systemId)

	if rootKey.IsExpired() {
		return "", fmt.Errorf("macaroon expired or deleted")
	}

	_, err = um.VerifySignature([]byte(rootKey.Key), nil)
	if err != nil {
		return "", fmt.Errorf("macaroon failed signature verification")
	}

	return systemId, nil
}

func (s *Server) CheckRequiredClaims(claims *CommonClaims, requiredTokenType string) error {
	if claims.ExpiresAt == 0 ||
		claims.IssuedAt == 0 ||
		claims.Issuer != "ssas" ||
		claims.Id == "" ||
		claims.TokenType == "" {
		return fmt.Errorf("missing one or more claims")
	}

	if requiredTokenType != claims.TokenType {
		return fmt.Errorf(fmt.Sprintf("wrong token type: %s; required type: %s", claims.TokenType, requiredTokenType))
	}
	return nil
}

func (s *Server) GetClientAssertionAudience() string {
	return s.clientAssertAud
}
