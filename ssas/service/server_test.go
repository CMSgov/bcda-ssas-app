package service

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
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
` // #nosec G101

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
` // #nosec G101

// b64 fake cert used for testing
const b64_test_cert = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURVVENDQWptZ0F3SUJBZ0lKQUx4eU8xN1NhQ2lmTUEwR0NTcUdTSWIzRFFFQkN3VUFNRkl4Q3pBSkJnTlYKQkFZVEFsVlRNUXN3Q1FZRFZRUUlEQUpEUVRFVE1CRUdBMVVFQnd3S1RHOXpRVzVuWld4bGN6RU5NQXNHQTFVRQpDZ3dFUVVOTlJURVNNQkFHQTFVRUF3d0piRzlqWVd4b2IzTjBNQjRYRFRJeE1USXdPREl6TURjMU5sb1hEVEl5Ck1USXdPREl6TURjMU5sb3dWakVMTUFrR0ExVUVCaE1DVlZNeEN6QUpCZ05WQkFnTUFrTkJNUk13RVFZRFZRUUgKREFwTWIzTkJibWRsYkdWek1SRXdEd1lEVlFRS0RBaEJRMDFGSUVGUVNURVNNQkFHQTFVRUF3d0piRzlqWVd4bwpiM04wTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUE3bDV4ZXY1QUtQS3E5RXY1CnBpZk5sNXdVYVZxRkREM2FOMmx0bzFqbkpFRkFvTWIvZGJub3Rta0R4N05yNElIUE1MMDAreklwVC9hQTBTNFEKZ3oyMjJZSVROZFZwenNDcTBpMXBDWm11Vm8yRkZQb3BBTXpzTnlac0ZSa1FXQkt3dDlwc3g1QklNTFpXUHNudAp5bHRQekcwMlZlb3BmVFI3VG9CSGQ1Smk0NnZWUFJSU3E5a1VET3o0TENDeElvYXlLT0swSjI1dWVMNVlzT205Ck9ROWJFRThSZDBIM3U3bjdrTURyNEVGeTdhZE0raEpJOGJ6Tkh3aTR1RUFEOXB0dHk3elFudDdiYlFCMnNRMEgKaEQzOVVQaU55aktKTHdFaHdPbnVlN1BVcmQrT2VpV3I5YXk5TWh6NlpTZWdxOVVGQXpVM3pxWlMyaE1CVU4rZApTS3grd3dJREFRQUJveVl3SkRBVUJnTlZIUkVFRFRBTGdnbHNiMk5oYkdodmMzUXdEQVlEVlIwVEJBVXdBd0VCCi96QU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFqR25Cem9TaXd4YjhsM3BCYW5KblM3N2FSK3dKcXdxTzdXN24KcnZSc2xYNVUrc1dja1JCdmVodENhL2Y2VVI1K1pzUmFOZit2N3RkMEZWS0RoVFdnY1E3aXowQmZDd0ZZUzNCZQpHbGtCT3pYem81czY3K0tVMllNd3lmSjhmYU10QU9lbW1meTN0eEt1K2UrM0t1dHhleG8vUTM1dGdxSGE1UGc1CjFrMVNmaGY1NGowaUhuOHlldDZBdWVUR3RqS0VBT3JHZkZjWlNXNEE2M0MwV0lGanZ5Yzc1czRKaUJ2WUd2MkgKZmxKbzdQTEtydmg3REhNS3E1YUV0NkdmN0M5OWhObGNPZnJaZXBYVExQaFdORGh0ZnhkZHVwMnJrZG4zYjBmdwpCR2JJeHNncmFucTFZUXJ3YWNENm5kazJORngzSkVpakhsNkkrb3FhK3FtREpMcm04QT09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K"

// fake cert key used for testing
const b64_test_cert_key = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcFFJQkFBS0NBUUVBN2w1eGV2NUFLUEtxOUV2NXBpZk5sNXdVYVZxRkREM2FOMmx0bzFqbkpFRkFvTWIvCmRibm90bWtEeDdOcjRJSFBNTDAwK3pJcFQvYUEwUzRRZ3oyMjJZSVROZFZwenNDcTBpMXBDWm11Vm8yRkZQb3AKQU16c055WnNGUmtRV0JLd3Q5cHN4NUJJTUxaV1BzbnR5bHRQekcwMlZlb3BmVFI3VG9CSGQ1Smk0NnZWUFJSUwpxOWtVRE96NExDQ3hJb2F5S09LMEoyNXVlTDVZc09tOU9ROWJFRThSZDBIM3U3bjdrTURyNEVGeTdhZE0raEpJCjhiek5Id2k0dUVBRDlwdHR5N3pRbnQ3YmJRQjJzUTBIaEQzOVVQaU55aktKTHdFaHdPbnVlN1BVcmQrT2VpV3IKOWF5OU1oejZaU2VncTlVRkF6VTN6cVpTMmhNQlVOK2RTS3grd3dJREFRQUJBb0lCQVFDNnVuczFPVFR6bnQyeQowRTE2RHRZc1BSVjBUbmZKVmk2Nmw3bE9hOWR0L0R2dmR0UXAyZi9sM1RBYjRYN1JlWDdnRkdnTG00am5YaGdkClJYT2tDOVZRWUdoQ0ZMTjFSbExLb000V3VpL3JGNk80QWh2YXg2MEhxdTZpUEdja1IwZnVUb3BHYnMxT2M1ZnUKU2VzZ1NSV2k4NjdMOE1xZGpWNUc2WkNTcDdjVjEwUGZDNmdzbjkvbXV0MVdYY0l2L3RhenJuYXpMbHk2N1NxNwpLei9RSlM2ZjR2WGE1TXMyMmc5aXJ1dmNFNnZ3SjUyMjYxdGdOS0hObE5mK1hDakozbkthV3ZPZlg0N1ZiTEJ0ClN4MDY3K083QjZOTHQ5bmI3TjcrUHcrR3hpVUc1bEd4aklJdzVZOElBKzdDWndzckcxWFFwblZ1TXhuTUdKdTkKYS8yRUt1aWhBb0dCQVA0UGg2VGNFMGJWaWhWYnBjd2hoVjQ0cS80N2NLZEpiSXJKcjZsaVFTUjZmZ0l4aHJQLwpOcFFWS1NJRG9Hb0lGK1FuUzRGSmIrSEhDSDFuYXNLeFI2ZVZnaWJSVlZWQU9EbUdEYS9Va3RuY2tGS3c3YzhyCm93Mm1PcXRsRDB5bEhEbjd2ZVI3QjBQRGNoWmkzTkpZc0FVODVXdllmOW1JMUF5Y1l0bWJDbjV4QW9HQkFQQXcKUCtMbXJOeVl1U0x4c2NTTzZPa2l2RmlPblZDOWJlUElPeW9saEZDam53bG90cG9KOGx0WTFmTzVJMExacWlyZgp0TDRPUU82TFEzVFJrVms4VU1acGlzVmJRR2JQWnpBckdDNjJVZUhwdmVSRWhUTGR2YkhCY2xWbmtJMDNCcE1VClczYkZhMjFqR3FkREgwZ0E4ZmFMZHhDUkpaZGY4YWxhdk1RVGpkSnpBb0dCQU93MWZDUG5DWFVlTEpmVzhidHMKbnhjUEVibjVnYS9ITUVlSlpPelRFVVhkTFRMVTRTeVE2Q21kMHZSdzhzQWlialFONU1GN2lhNGM0dVBWTndsMAowZTRacnp4di9DcWEzcXQ4MjFUVEN3WExiOU94OUNoZHBlZVcyWTFwRkdScVRtZ0tpbTdYZzlXWTdZV3F2U3hFCmtNTU43eS9weGxSMlJ0REN4WlVUOVJuQkFvR0FLenBUMVM5MC93TFJsek51cmhTV1lKY3ExTGxlSU5EbS9TN2wKVHhHUGZiL2srSm1LKzdBOG1Tb2szNGQ3akNXR2xjN0xSY1ZrOUVuR0t6a29jcW9EVTZKZEltWG84bGZ6bDF5NgpMbllMeUovNzJDQm81SjI1N1VzR204NVcyc09EZ0djU2l3Nis1ZUlIUXdFMm1RdnFnRmZiWnZUb2toVG5kblpwCk1OVGdHbmNDZ1lFQXI3SlNJa0g4ZndNNUhnSGRUSXZMTEExWGZXaU1rNGJPMGcvbEFSV08vY04xUVhFVkFXemIKWDR6djNPYWh5L0RCNERBWk5NN1JnQVhnNUdxbFhpTHlVQk5mMFVwU2s4cElDZEZkbGtLUnlJZTI4S1pHb3NNdQpmbzVxbHJMSndmdjBtZHV2U2RBVVNtTWlkZVdlQnVhNzdaZFlqVVBZVlA5dFNRVjhlbFhCUXJNPQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo="

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
	s.server = NewServer("test-server", ":9999", "9.99.999", s.info, nil, true, false, s.privateKey, 37*time.Minute, "")
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
	ts := NewServer("test-server", ":9999", "9.99.999", s.info, r, true, false, s.privateKey, 37*time.Minute, "")
	assert.NotEmpty(s.T(), ts.router)
	routes, err := ts.ListRoutes()
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), routes)
	expected := []string{"GET /_health", "GET /_info", "GET /_version", "GET /test"}
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
	ts := NewServer("test-server", ":9999", "9.99.999", s.info, r, true, false, nil, 37*time.Minute, "")
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

	ts := NewServer("test-server", ":9999", "9.99.999", s.info, r, true, false, invalidPrivateKey, 37*time.Minute, "")
	assert.Nil(s.T(), ts)
}

// test Server() ? how????

func (s *ServerTestSuite) TestGetInfo() {
	req := httptest.NewRequest("GET", "/_info", nil)
	handler := http.HandlerFunc(s.server.getInfo)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	b, _ := io.ReadAll(rr.Result().Body)
	assert.Contains(s.T(), string(b), `{"public":["token","register"]}`)
}

func (s *ServerTestSuite) TestGetVersion() {
	req := httptest.NewRequest("GET", "/_version", nil)
	handler := http.HandlerFunc(s.server.getVersion)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	b, _ := io.ReadAll(rr.Result().Body)
	assert.Contains(s.T(), string(b), `{"version":"9.99.999"}`)
}

func (s *ServerTestSuite) TestGetHealthCheck() {
	req := httptest.NewRequest("GET", "/_health", nil)
	handler := http.HandlerFunc(s.server.getHealthCheck)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	b, _ := io.ReadAll(rr.Result().Body)
	assert.Contains(s.T(), string(b), `{"database":"ok"}`)
}

func (s *ServerTestSuite) TestNYI() {
	req := httptest.NewRequest("GET", "/random_endpoint", nil)
	handler := http.HandlerFunc(NYI)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(s.T(), http.StatusOK, rr.Result().StatusCode)
	b, _ := io.ReadAll(rr.Result().Body)
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

func (s *ServerTestSuite) TestMTLCertParsing() {
	os.Setenv("BCDA_TLS_CERT_B64", b64_test_cert)
	defer os.Unsetenv("BCDA_TLS_CERT_B64")

	os.Setenv("BCDA_TLS_KEY_B64", b64_test_cert_key)
	defer os.Unsetenv("BCDA_TLS_KEY_B64")

	config, err := BuildMTLSConfig()
	assert.Nil(s.T(), err)
	assert.NotNil(s.T(), config)
}

func (s *ServerTestSuite) TestMTLCertParsingWithMissingCert() {
	// Ensure cer key is set
	os.Setenv("BCDA_TLS_KEY_B64", b64_test_cert_key)
	defer os.Unsetenv("BCDA_TLS_KEY_B64")

	// Ensure cert is NOT set
	os.Unsetenv("BCDA_TLS_CERT_B64")

	config, err := BuildMTLSConfig()
	assert.Nil(s.T(), config)
	expected := "one of the following required environment variables is missing or not base64 encoded: BCDA_TLS_CERT_B64, BCDA_TLS_KEY_B64"
	assert.Equal(s.T(), expected, err.Error())
}

func (s *ServerTestSuite) TestMTLCertParsingWithMissingCertKey() {
	// Ensure cert is set
	os.Setenv("BCDA_TLS_CERT_B64", b64_test_cert)
	defer os.Unsetenv("BCDA_TLS_CERT_B64")

	// Ensure cert key is NOT set
	os.Unsetenv("BCDA_TLS_KEY_B64")

	config, err := BuildMTLSConfig()
	assert.Nil(s.T(), config)
	expected := "one of the following required environment variables is missing or not base64 encoded: BCDA_TLS_CERT_B64, BCDA_TLS_KEY_B64"
	assert.Equal(s.T(), expected, err.Error())
}

func (s *ServerTestSuite) TestMTLCertParsingWithInvalidCert() {
	os.Setenv("BCDA_TLS_CERT_B64", "invalid base 64 encoded cert")
	defer os.Unsetenv("BCDA_TLS_CERT_B64")

	os.Setenv("BCDA_TLS_KEY_B64", b64_test_cert_key)
	defer os.Unsetenv("BCDA_TLS_KEY_B64")

	config, err := BuildMTLSConfig()
	assert.Nil(s.T(), config)
	expected := "could not base64 decode BCDA_TLS_CERT_B64"
	assert.Equal(s.T(), expected, err.Error())
}

func (s *ServerTestSuite) TestMTLCertParsingWithInvalidCertKey() {
	os.Setenv("BCDA_TLS_CERT_B64", b64_test_cert)
	defer os.Unsetenv("BCDA_TLS_CERT_B64")

	os.Setenv("BCDA_TLS_KEY_B64", "invalid base64 cert key")
	defer os.Unsetenv("BCDA_TLS_KEY_B64")

	config, err := BuildMTLSConfig()
	assert.Nil(s.T(), config)
	expected := "could not base64 decode BCDA_TLS_KEY_B64"
	assert.Equal(s.T(), expected, err.Error())
}

func (s *ServerTestSuite) TestMTLCertParsingWithInvalidCertValue() {
	os.Setenv("BCDA_TLS_CERT_B64", "aW52YWxpZCB2YWx1ZSBpbiBiYXNlIDY0")
	defer os.Unsetenv("BCDA_TLS_CERT_B64")

	os.Setenv("BCDA_TLS_KEY_B64", b64_test_cert_key)
	defer os.Unsetenv("BCDA_TLS_KEY_B64")

	config, err := BuildMTLSConfig()
	assert.Nil(s.T(), config)
	expected := "failed to parse server cert"
	assert.Equal(s.T(), expected, err.Error())
}

func (s *ServerTestSuite) TestMTLCertParsingWithInvalidCertKeyValue() {
	os.Setenv("BCDA_TLS_CERT_B64", b64_test_cert)
	defer os.Unsetenv("BCDA_TLS_CERT_B64")

	os.Setenv("BCDA_TLS_KEY_B64", "aW52YWxpZCB2YWx1ZSBpbiBiYXNlIDY0")
	defer os.Unsetenv("BCDA_TLS_KEY_B64")

	config, err := BuildMTLSConfig()
	assert.Nil(s.T(), config)
	expected := "failed to parse server cert/key pair"
	assert.Equal(s.T(), expected, err.Error())
}

// test ConnectionClose()

// MintToken(), MintTokenWithDuration()

func (s *ServerTestSuite) TestNewServerWithBadSigningKey() {
	ts := NewServer("test-server", ":9999", "9.99.999", s.info, nil, true, false, nil, 37*time.Minute, "")
	assert.Nil(s.T(), ts)
}

func TestServerTestSuite(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
}
