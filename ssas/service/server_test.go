package service

import (
	"crypto/rand"
	"crypto/rsa"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// unit test private key path
const unitSigningKeyPath string = "../../shared_files/ssas/unit_test_private_key.pem"

// ../../shared_files/ssas/public_test_signing_key.pem
const unitSigningKey string = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx10/H+MobMJ7LMyaWOU4XKcHai0CSUULI0tWSow6G8CTPYPK
W9L3RU02vkOywdpJ8skkSqDPUmyBi5+Mp2idA7oHXCyY6mV2p0q/QZWvODm8hnP9
F5eIt4GbyVzH1/Md4rwlIsZEZ/C98wTpRJyLtORbXjteRloxLvL9teVwYF2wWHCM
jQqUbEagOcM5BbFRMt9QvQFbDWGAbRJSCUXfswzcTU3ZD+hFkudBahDn58Sl8T3F
GrAb7TEtdfMRH9gC8jOKO26ol0wNrACZYUYPUVOiDUGP0q5zxSysm+AIOV3u74Zf
R/ShQRwjrAvzRmIcQrjGfZPbT6xmn15Wcp3nRQIDAQABAoIBAQCezVTZ5oytzWBm
N/f+NV/m1ZlfZsi6akfL7lem+/nRX10pk8/dwrb6Od4QQkaiiWl7/eJtm5hpFEtA
V2+nbfocHNN+BXwswXN5IF4mNMAkrkDQbJW+dBMP8SqRg9kf1+UHVUzTXVDh5m63
pELXR0c1aOyqq+mVaoRg3Gdhu4f/CVnF0iDnIu6ieU8NivUuQOUzoYFLdlmgKPKS
oqbPd+9ARgMYo2oPIWChkfK/fcJVWHZmvorZudknRRKEYQ26pFLNLdj3v2lkAJyT
s61mCSD5fVVH/+CovcUXvvhxZUOY7k9mWkD2ovVyyCSTEfhVizilzxic0NWAtBMi
oATNDL3FAoGBAOfv02msvDUc4JCJ6mpjDbRD8YMmClveLV9fW5S05uPR7cO4ABke
Elw4pDtf3YGVirKDvnJi4+z5y2IqJbY5Gj5FPCAK1qW247hmKCpZ5YVYTaoM5dDp
4HAdyiaBmxVID194EGM+DNxMnUxV4G7/uWCTNuMDvdNeXvx5mM3pC/0vAoGBANwM
TXummjU1OMVYEQMzFETSX/AFN39weN+uaOHuk5H1VEwG9av2n+VYqQicvNQPlnwE
FStvpwRfzsnSnQa7UlSq2EOpXvLKJ0tXQM77BsM6YGN6sOx/i2yxjOcXPrsYfWBr
gv48dxxjd/RMVb4TfmB/Li0nLZbUq5/4PONZG03LAoGAd5yhBNCGR0XbMe9OKwtm
V97qQF5v3SzZbWP6ENiyci8jVVohAtMVWOYFHHG2BEwguStkHg2NyfqQvtFJnY4Z
UJ/YABZW2CNXkRNuB1lRGtGNS/NW2cSjcG6MgAs69WCyPOPoX6Xyb/I69NEc62GK
Mpn5Jl4ZmVYD2mTDPv2+pxUCgYEAgckH0kx7W7KeX1cIAbkY1Va3mxuYliPCRzvZ
RJiwlT/7jjP0po551I2sdRXtEa539YF68vmRqrTPhJ4iW5wUfTefApldFRpCft9h
rDLG1FMUEtiEjZjUpTE7h/lf2H4jRMFkq4sCPc41K/PyBn/84/FfTOZ0ryeUam/B
id4+im0CgYBWNojHUhucKK1z+LCZHy5pcvC4GGAX4gGOjZNvAXayicx/IZPYrzfk
Xm02FAag9/6ZHIetBAStHVlwSApXd74FlCdeqWPpN6aY4MbIlA4hDm1PGzm/Esho
gQyVVpMFC4AdUlq5wZmXEGq3chOILurZS3B5BbICQJCDan/6a3YVPQ==
-----END RSA PRIVATE KEY-----
`

// unit test private key path
const invalidKeyPath string = "../../shared_files/ssas/unit_test_bad_private_key.pem"

const invalidKey string = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx10/H+MobMJ7LMyaWOU4XKcHai0CSUULI0tWSow6G8CTPYPK
W9L3RU02vkOywdpJ8skkSqDPUmyBi5+Mp2idA7oHXCyY6mV2p0q/QZWvODm8hnP9
F5eIt4GbyVzH1/Md4rwlIsZEZ/C98wTpRJyLtORbXjteRloxLvL9teVwYF2wWHCM
jQqUbEagOcM5BbFRMt9QvQFbDWGAbRJSCUXfswzcTU3ZD+hFkudBahDn58Sl8T3F
GrAb7TEtdfMRH9gC8jOKO26ol0wNrACZYUYPUVOiDUGP0q5zxSysm+AIOV3u74Zf
R/ShQRwjrAvzRmIcQrjGfZPbT6xmn15Wcp3nRQIDAQABAoIBAQCezVTZ5oytzWBm
N/f+NV/m1ZlfZsi6akfL7lem+/nRX10pk8/dwrb6Od4QQkaiiWl7/eJtm5hpFEtA
V2+nbfocHNN+BXwswXN5IF4mNMAkrkDQbJW+dBMP8SqRg9kf1+UHVUzTXVDh5m63
pELXR0c1aOyqq+mVaZRg3Gdhu4f/CVnF0iDnIu6ieU8NivUuQOUzoYFLdlmgKPKS
oqbPd+9ARgMYo2oPIWChkfK/fcJVWHZmvorZudknRRKEYQ26pFLNLdj3v2lkAJyT
s61mCSD5fVVH/+CovcUXvvhxZUOY7k9mWkD2ovVyyCSTEfhVizilzxic0NWAtBMi
oATNDL3FAoGBAOfv02msvDUc4JCJ6mpjDbRD8YMmClveLV9fW5S05uPR7cO4ABke
Elw4pDtf3YGVirKDvnJi4+z5y2IqJbY5Gj5FPCAK1qW247hmKCpZ5YVYTaoM5dDp
4HAdyiaBmxVID194EGM+DNxMnUxV4G7/uWCTNuMDvdNeXvx5mM3pC/0vAoGBANwM
TXummjU1OMVYEQMzFETSX/AFN39weN+uaOHuk5H1VEwG9av2n+VYqQicvNQPlnwE
FStvpwRfzsnSnQa7UlSq2EOpXvLKJ0tXQM77BsM6YGN6sOx/i2yxjOcXPrsYfWBr
gv48dxxjd/RMVb4TfmB/Li0nLZbUq5/4PONZG03LAoGAd5yhBNCGR0XbMe9OKwtm
V97qQF5v3SzZbWP6ENiyci8jVVohAtMVWOYFHHG2BEwguStkHg2NyfqQvtFJnY4Z
UJ/YABZW2CNXkRNuB1lRGtGNS/NW2cSjcG6MgAs69WCyPOPoX6Xyb/I69NEc62GK
Mpn5Jl4ZmVYD2mTDPv2+pxUCgYEAgckH0kx7W7KeX1cIAbkY1Va3mxuYliPCRzvZ
RJiwlT/7jjP0po551I2sdRXtEa539YF68vmRqrTPhJ4iW5wUfTefApldFRpCft9h
rDLG1FMUEtiEjZjUpTE7h/lf2H4jRMFkq4sCPc41K/PyBn/84/FfTOZ0ryeUam/B
id4+im0CgYBWNojHUhucKK1z+LCZHy5pcvC4GGAX4gGOjZNvAXayicx/IZPYrzfk
Xm02FAag9/6ZHIetBAStHVlwSApXd74FlCdeqWPpN6aY4MbIlA4hDm1PGzm/Esho
gQyVVpMFC4AdUlq5wZmXEGq3chOILurZS3B5BbICQJCDan/6a3YVPQ==
-----END RSA PRIVATE KEY-----
`

type ServerTestSuite struct {
	suite.Suite
	server     *Server
	info       map[string][]string
	privateKey *rsa.PrivateKey
}

func (s *ServerTestSuite) SetupSuite() {
	s.info = make(map[string][]string)
	s.info["public"] = []string{"token", "register"}
	s.privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
}

func (s *ServerTestSuite) SetupTest() {
	s.server = NewServer("test-server", ":9999", "9.99.999", s.info, nil, true, s.privateKey, 37*time.Minute, "")
}

func (s *ServerTestSuite) TestNewServer() {
	assert.NotNil(s.T(), s.server)
	assert.NotNil(s.T(), s.server.tokenSigningKey)
	assert.NotEmpty(s.T(), s.server.name)
	assert.NotEmpty(s.T(), s.server.port)
	assert.NotEmpty(s.T(), s.server.version)
	assert.NotEmpty(s.T(), s.server.info)
	assert.NotEmpty(s.T(), s.server.router)
	assert.True(s.T(), s.server.notSecure)
	assert.NotNil(s.T(), s.server.tokenSigningKey)
	assert.NotZero(s.T(), s.server.tokenTTL)

	r := chi.NewRouter()
	r.Get("/test", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("test"))
	})
	ts := NewServer("test-server", ":9999", "9.99.999", s.info, r, true, s.privateKey, 37*time.Minute, "")
	assert.NotEmpty(s.T(), ts.router)
	routes, err := ts.ListRoutes()
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), routes)
	expected := []string{"GET /_health", "GET /_info", "GET /_version", "GET /*/test"}
	assert.Equal(s.T(), expected, routes)
}

func (s *ServerTestSuite) TestNewServerNilPrivateKey() {
	assert.NotNil(s.T(), s.server)
	assert.NotNil(s.T(), s.server.tokenSigningKey)
	assert.NotEmpty(s.T(), s.server.name)
	assert.NotEmpty(s.T(), s.server.port)
	assert.NotEmpty(s.T(), s.server.version)
	assert.NotEmpty(s.T(), s.server.info)
	assert.NotEmpty(s.T(), s.server.router)
	assert.True(s.T(), s.server.notSecure)
	assert.NotNil(s.T(), s.server.tokenSigningKey)
	assert.NotZero(s.T(), s.server.tokenTTL)

	r := chi.NewRouter()
	r.Get("/test", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("test"))
	})
	ts := NewServer("test-server", ":9999", "9.99.999", s.info, r, true, nil, 37*time.Minute, "")
	assert.Nil(s.T(), ts)
}

func (s *ServerTestSuite) TestNewServerInvalidPrivateKey() {
	assert.NotNil(s.T(), s.server)
	assert.NotNil(s.T(), s.server.tokenSigningKey)
	assert.NotEmpty(s.T(), s.server.name)
	assert.NotEmpty(s.T(), s.server.port)
	assert.NotEmpty(s.T(), s.server.version)
	assert.NotEmpty(s.T(), s.server.info)
	assert.NotEmpty(s.T(), s.server.router)
	assert.True(s.T(), s.server.notSecure)
	assert.NotNil(s.T(), s.server.tokenSigningKey)
	assert.NotZero(s.T(), s.server.tokenTTL)

	r := chi.NewRouter()
	r.Get("/test", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("test"))
	})

	invalidPrivateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// mess with the key to invalidate it
	invalidPrivateKey.D = big.NewInt(2)

	ts := NewServer("test-server", ":9999", "9.99.999", s.info, r, true, invalidPrivateKey, 37*time.Minute, "")
	assert.Nil(s.T(), ts)
}

// test Server() ? how????

func (s *ServerTestSuite) TestGetInfo() {
	req := httptest.NewRequest("GET", "/_info", nil)
	handler := http.HandlerFunc(s.server.getInfo)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	b, _ := ioutil.ReadAll(rr.Result().Body)
	assert.Contains(s.T(), string(b), `{"public":["token","register"]}`)
}

func (s *ServerTestSuite) TestGetVersion() {
	req := httptest.NewRequest("GET", "/_version", nil)
	handler := http.HandlerFunc(s.server.getVersion)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	b, _ := ioutil.ReadAll(rr.Result().Body)
	assert.Contains(s.T(), string(b), `{"version":"9.99.999"}`)
}

func (s *ServerTestSuite) TestGetHealthCheck() {
	req := httptest.NewRequest("GET", "/_health", nil)
	handler := http.HandlerFunc(s.server.getHealthCheck)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	b, _ := ioutil.ReadAll(rr.Result().Body)
	assert.Contains(s.T(), string(b), `{"database":"ok"}`)
}

func (s *ServerTestSuite) TestNYI() {
	req := httptest.NewRequest("GET", "/random_endpoint", nil)
	handler := http.HandlerFunc(NYI)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	b, _ := ioutil.ReadAll(rr.Result().Body)
	assert.Contains(s.T(), string(b), "Not Yet Implemented")
}

func (s *ServerTestSuite) TestChooseSigningKeyBothSet() {
	// if both env vars are set, error out.
	_, err := ChooseSigningKey(unitSigningKeyPath, unitSigningKey)
	assert.Error(s.T(), err, "inline key or path must be set, but not both")
}

func (s *ServerTestSuite) TestChooseSigningKeyNeitherSet() {
	// if neither env vars are set, error out.
	_, err := ChooseSigningKey("", "")
	assert.Error(s.T(), err, "inline key and path are both empty strings")
}

func (s *ServerTestSuite) TestChooseSigningKeyUsingInline() {
	// having the inline private key set
	sk, _ := ChooseSigningKey("", unitSigningKey)
	assert.Equal(s.T(), nil, sk.Validate())
}

func (s *ServerTestSuite) TestChooseSigningKeyUsingFile() {
	// having the private key file set
	sk, _ := ChooseSigningKey(unitSigningKeyPath, "")
	assert.Equal(s.T(), nil, sk.Validate())
}

func (s *ServerTestSuite) TestChooseSigningKeyUsingInvalidInline() {
	// having the inline private key set but is invalid
	_, err := ChooseSigningKey("", invalidKey)
	assert.Error(s.T(), err, "bad inline signing key")
}

func (s *ServerTestSuite) TestChooseInvalidSigningKeyUsingFile() {
	// having the private key file set but is invalid
	_, err := ChooseSigningKey(invalidKeyPath, "")
	assert.Error(s.T(), err, "bad signing key")
}

// test ConnectionClose()

// MintToken(), MintTokenWithDuration()

func (s *ServerTestSuite) TestNewServerWithBadSigningKey() {
	ts := NewServer("test-server", ":9999", "9.99.999", s.info, nil, true, nil, 37*time.Minute, "")
	assert.Nil(s.T(), ts)
}

func TestServerTestSuite(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
}
