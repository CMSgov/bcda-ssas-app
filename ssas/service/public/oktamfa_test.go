package public

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/CMSgov/bcda-ssas-app/ssas/okta"
	"github.com/pborman/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"
)

type OTestSuite struct {
	suite.Suite
}

type TestResponse struct {
	GiveAnswer func(*http.Request) bool
	Response   *http.Response
}

func (s *OTestSuite) TestPostFactorResponseInvalidToken() {
	trackingId := uuid.NewRandom().String()
	userId := "abc123"
	passcode := "not_a_passcode"
	factor := Factor{Id: "123abc", Type: "call"}
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		assert.Equal(s.T(), req.URL.String(), okta.OktaBaseUrl+"/api/v1/users/"+userId+"/factors/"+factor.Id+"/verify")
		b, err := ioutil.ReadAll(req.Body)
		assert.Nil(s.T(), err)
		assert.Equal(s.T(), fmt.Sprintf(`{"passCode":"%s"}`, passcode), string(b))
		return testHttpResponse(401, `{"errorCode":"E0000011","errorSummary":"Invalid token provided","errorLink":"E0000011","errorId":"oaeBRew9Pp3Rq-6jNarZEpmAg","errorCauses":[]}`)
	})

	o := NewOktaMFA(client)
	factorResponse, err := o.postFactorResponse(userId, factor, passcode, trackingId)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), factorResponse)
}

func (s *OTestSuite) TestPostFactorResponseInvalidPasscode() {
	trackingId := uuid.NewRandom().String()
	userId := "abc123"
	passcode := "not_a_passcode"
	factor := Factor{Id: "123abc", Type: "call"}
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		assert.Equal(s.T(), req.URL.String(), okta.OktaBaseUrl+"/api/v1/users/"+userId+"/factors/"+factor.Id+"/verify")
		b, err := ioutil.ReadAll(req.Body)
		assert.Nil(s.T(), err)
		assert.Equal(s.T(), fmt.Sprintf(`{"passCode":"%s"}`, passcode), string(b))
		return testHttpResponse(403, `{"errorCode":"E0000068","errorSummary":"Invalid Passcode/Answer","errorLink":"E0000068","errorId":"oaeZAX9ava1RYS8lWNksxtqeg","errorCauses":[{"errorSummary":"Your token doesn't match our records. Please try again."}]}`)
	})

	o := NewOktaMFA(client)
	factorResponse, err := o.postFactorResponse(userId, factor, passcode, trackingId)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), factorResponse)
}

func (s *OTestSuite) TestPostFactorResponseSuccess() {
	trackingId := uuid.NewRandom().String()
	userId := "abc123"
	passcode := "not_a_passcode"
	factor := Factor{Id: "123abc", Type: "call"}
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		assert.Equal(s.T(), req.URL.String(), okta.OktaBaseUrl+"/api/v1/users/"+userId+"/factors/"+factor.Id+"/verify")
		b, err := ioutil.ReadAll(req.Body)
		assert.Nil(s.T(), err)
		assert.Equal(s.T(), fmt.Sprintf(`{"passCode":"%s"}`, passcode), string(b))
		return testHttpResponse(200, `{"factorResult":"SUCCESS"}`)
	})

	o := NewOktaMFA(client)
	factorResponse, err := o.postFactorResponse(userId, factor, passcode, trackingId)
	if err != nil || factorResponse == nil {
		assert.FailNow(s.T(), "no response object returned")
	}
	assert.Equal(s.T(), "SUCCESS", factorResponse.Result)
}

func (s *OTestSuite) TestPostFactorChallengeSuccess() {
	trackingId := uuid.NewRandom().String()
	userId := "abc123"
	factor := Factor{Id: "123abc", Type: "call"}
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		assert.Equal(s.T(), req.URL.String(), okta.OktaBaseUrl+"/api/v1/users/"+userId+"/factors/"+factor.Id+"/verify")
		return testHttpResponse(200, `{"factorResult":"CHALLENGE","_links":{"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc/verify","hints":{"allow":["POST"]}},"factor":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc","hints":{"allow":["GET","DELETE"]}}}}`)
	})

	o := NewOktaMFA(client)
	factorVerification, err := o.postFactorChallenge(userId, factor, trackingId)
	if err != nil || factorVerification == nil {
		s.FailNow("factor result not parsed")
	}
	assert.Equal(s.T(), "CHALLENGE", factorVerification.Result)
}

func (s *OTestSuite) TestPostFactorChallengePushSuccess() {
	trackingId := uuid.NewRandom().String()
	userId := "abc123"
	factor := Factor{Id: "123mno", Type: "push"}
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		assert.Equal(s.T(), req.URL.String(), okta.OktaBaseUrl+"/api/v1/users/"+userId+"/factors/"+factor.Id+"/verify")
		return testHttpResponse(200, `{"factorResult":"WAITING","profile":{"credentialId":"bcda_user1@cms.gov","deviceType":"SmartPhone_IPhone","keys":[{"kty":"PKIX","use":"sig","kid":"default","x5c":["MIIBI..."]}],"name":"User’s iPhone","platform":"IOS","version":"12.1.2"},"expiresAt":"2019-07-12T14:21:30.000Z","_links":{"cancel":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno/transactions/v2mst.WmiSGGkvQc6P-QUQ5Qy0jg","hints":{"allow":["DELETE"]}},"poll":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno/transactions/v2mst.WmiSGGkvQc6P-QUQ5Qy0jg","hints":{"allow":["GET"]}}}}`)
	})

	o := NewOktaMFA(client)
	factorVerification, err := o.postFactorChallenge(userId, factor, trackingId)
	if err != nil || factorVerification == nil {
		s.FailNow("factor result not parsed")
	}
	expectedTime, err := time.Parse("2006-01-02T15:04:05.999Z", "2019-07-12T14:21:30.000Z")
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), expectedTime, factorVerification.ExpiresAt)
	assert.Equal(s.T(), "WAITING", factorVerification.Result)
	assert.Equal(s.T(), "https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno/transactions/v2mst.WmiSGGkvQc6P-QUQ5Qy0jg", factorVerification.Links.Poll.Href)
}

func (s *OTestSuite) TestPostFactorChallengeFactorNotFound() {
	trackingId := uuid.NewRandom().String()
	userId := "abc123"
	factor := Factor{Id: "nonexistent_factor", Type: "call"}
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		assert.Equal(s.T(), req.URL.String(), okta.OktaBaseUrl+"/api/v1/users/"+userId+"/factors/"+factor.Id+"/verify")
		return testHttpResponse(404, `{"errorCode":"E0000007","errorSummary":"Not found: Resource not found: nonexistent_factor (UserFactor)","errorLink":"E0000007","errorId":"oaeTd-sjkYlSuKXMVPzEb4okw","errorCauses":[]}`)
	})

	o := NewOktaMFA(client)
	factorVerification, err := o.postFactorChallenge(userId, factor, trackingId)
	assert.Empty(s.T(), factorVerification)
	if err == nil {
		s.FailNow("postFactorChallenge() should fail on invalid factor ID")
	}
	assert.Contains(s.T(), err.Error(), "Resource not found")
}

func (s *OTestSuite) TestPostPasswordSuccess() {
	trackingId := uuid.NewRandom().String()
	userId := "abc123"
	password, err := randomCharacters(16)
	require.Nil(s.T(), err)
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		assert.Equal(s.T(), req.URL.String(), okta.OktaBaseUrl+"/api/v1/authn")
		b, err := ioutil.ReadAll(req.Body)
		assert.Nil(s.T(), err)
		assert.Equal(s.T(), fmt.Sprintf(`{"username":"%s","password":"%s"}`, userId, password), string(b))
		return testHttpResponse(200, `{"stateToken":"00zABCabc123-000","expiresAt":"2019-09-16T19:28:58.000Z","status":"MFA_REQUIRED","_embedded":{"user":{"id":"abc123","passwordChanged":"2019-07-23T20:03:32.000Z","profile":{"login":"bcda_user2@cms.gov","firstName":"ACO","lastName":"User2","locale":"en","timeZone":"America/Los_Angeles"}},"factors":[{"id":"123ghi","factorType":"sms","provider":"OKTA","vendorName":"OKTA","profile":{"phoneNumber":"+1 XXX-XXX-7922"},"_links":{"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/authn/factors/123ghi/verify","hints":{"allow":["POST"]}}}}],"policy":{"allowRememberDevice":true,"rememberDeviceLifetimeInMinutes":30,"rememberDeviceByDefault":false,"factorsPolicyInfo":{}}},"_links":{"cancel":{"href":"https://cms-sandbox.oktapreview.com/api/v1/authn/cancel","hints":{"allow":["POST"]}}}}`)
	})

	o := NewOktaMFA(client)
	passwordResponse, err := o.postPassword(userId, password, trackingId)
	if err != nil || passwordResponse == nil {
		assert.FailNow(s.T(), "no response object returned")
	}
	assert.Equal(s.T(), "MFA_REQUIRED", passwordResponse.Status)
}

func (s *OTestSuite) TestPostPasswordFailure() {
	trackingId := uuid.NewRandom().String()
	userId := "abc123"
	password, err := randomCharacters(16)
	require.Nil(s.T(), err)
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		assert.Equal(s.T(), req.URL.String(), okta.OktaBaseUrl+"/api/v1/authn")
		b, err := ioutil.ReadAll(req.Body)
		assert.Nil(s.T(), err)
		assert.Equal(s.T(), fmt.Sprintf(`{"username":"%s","password":"%s"}`, userId, password), string(b))
		return testHttpResponse(401, `{"errorCode":"E0000004","errorSummary":"Authentication failed","errorLink":"E0000004","errorId":"oae_JnAectySpajMuJA3dqs7g","errorCauses":[]}`)
	})

	o := NewOktaMFA(client)
	passwordResponse, err := o.postPassword(userId, password, trackingId)
	if err != nil || passwordResponse == nil {
		assert.FailNow(s.T(), "no response object returned")
	}
	assert.Equal(s.T(), "AUTHENTICATION_FAILED", passwordResponse.Status)
}

func (s *OTestSuite) TestPostPasswordBadRequest() {
	trackingId := uuid.NewRandom().String()
	userId := "abc123"
	password := ""
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		assert.Equal(s.T(), req.URL.String(), okta.OktaBaseUrl+"/api/v1/authn")
		b, err := ioutil.ReadAll(req.Body)
		assert.Nil(s.T(), err)
		assert.Equal(s.T(), fmt.Sprintf(`{"username":"%s","password":""}`, userId), string(b))
		return testHttpResponse(400, `{"errorCode":"E0000001","errorSummary":"Api validation failed: authRequest","errorLink":"E0000001","errorId":"oaebM8KyzEVS5uMiImx4sHzGg","errorCauses":[{"errorSummary":"The 'username' and 'password' attributes are required in this context."}]}`)
	})

	o := NewOktaMFA(client)
	passwordResponse, err := o.postPassword(userId, password, trackingId)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), passwordResponse)
}

func (s *OTestSuite) TestGetUserHeaders() {
	trackingId := uuid.NewRandom().String()
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		assert.Contains(s.T(), req.Header.Get("Authorization"), "SSWS")
		assert.Equal(s.T(), req.Header.Get("Content-Type"), "application/json")
		assert.Equal(s.T(), req.Header.Get("Accept"), "application/json")
		return testHttpResponse(200, `[]`)
	})

	o := NewOktaMFA(client)
	_, _ = o.getUser("nonexistent_user", trackingId)
}

func (s *OTestSuite) TestGetUserSuccess() {
	trackingId := uuid.NewRandom().String()
	expectedUserId := "abc123"
	searchString := "a_user@cms.gov"
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		assert.Equal(s.T(), req.URL.String(), okta.OktaBaseUrl+"/api/v1/users/?q="+searchString)
		return testHttpResponse(200, `[{"id":"abc123","status":"ACTIVE","created":"2018-12-05T19:48:17.000Z","activated":"2018-12-05T19:48:17.000Z","statusChanged":"2019-06-04T12:52:49.000Z","lastLogin":"2019-06-06T18:45:35.000Z","lastUpdated":"2019-06-04T12:52:49.000Z","passwordChanged":"2019-06-04T12:52:49.000Z","profile":{"firstName":"Test","lastName":"User","mobilePhone":null,"addressType":"Select Type...","secondEmail":"a_user@cms.gov","login":"a_user@cms.gov","email":"a_user@cms.gov","LOA":"3"},"credentials":{"password":{},"emails":[{"value":"a_user@cms.gov","status":"VERIFIED","type":"PRIMARY"},{"value":"a_user@cms.gov","status":"VERIFIED","type":"SECONDARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123"}}}]`)
	})

	o := NewOktaMFA(client)
	foundUserId, err := o.getUser(searchString, trackingId)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), expectedUserId, foundUserId)
}

func (s *OTestSuite) TestGetUserBadStatusCode() {
	trackingId := uuid.NewRandom().String()
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		return testHttpResponse(404, "")
	})

	o := NewOktaMFA(client)
	foundUserId, err := o.getUser("user_irrelevant", trackingId)
	if err == nil {
		s.FailNow("getUser() should fail unless status code = 200")
	}
	assert.Contains(s.T(), err.Error(), "status code")
	assert.Equal(s.T(), "", foundUserId)
}

func (s *OTestSuite) TestGetUserNotLOA3() {
	trackingId := uuid.NewRandom().String()
	searchString := "a_user@cms.gov"
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		return testHttpResponse(200, `[{"id":"abc123","status":"ACTIVE","created":"2018-12-05T19:48:17.000Z","activated":"2018-12-05T19:48:17.000Z","statusChanged":"2019-06-04T12:52:49.000Z","lastLogin":"2019-06-06T18:45:35.000Z","lastUpdated":"2019-06-04T12:52:49.000Z","passwordChanged":"2019-06-04T12:52:49.000Z","profile":{"firstName":"Test","lastName":"User","mobilePhone":null,"addressType":"Select Type...","secondEmail":"a_user@cms.gov","login":"a_user@cms.gov","email":"a_user@cms.gov"},"credentials":{"password":{},"emails":[{"value":"a_user@cms.gov","status":"VERIFIED","type":"PRIMARY"},{"value":"a_user@cms.gov","status":"VERIFIED","type":"SECONDARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123"}}}]`)
	})

	o := NewOktaMFA(client)
	foundUserId, err := o.getUser(searchString, trackingId)
	if err == nil {
		s.FailNow("getUser() should fail unless LOA=3")
	}
	assert.Contains(s.T(), err.Error(), "LOA")
	assert.Equal(s.T(), "", foundUserId)
}

func (s *OTestSuite) TestGetUserNotActive() {
	trackingId := uuid.NewRandom().String()
	searchString := "a_user@cms.gov"
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		return testHttpResponse(200, `[{"id":"abc123","status":"STAGED","created":"2018-12-05T19:48:17.000Z","activated":"2018-12-05T19:48:17.000Z","statusChanged":"2019-06-04T12:52:49.000Z","lastLogin":"2019-06-06T18:45:35.000Z","lastUpdated":"2019-06-04T12:52:49.000Z","passwordChanged":"2019-06-04T12:52:49.000Z","profile":{"firstName":"Test","lastName":"User","mobilePhone":null,"addressType":"Select Type...","secondEmail":"a_user@cms.gov","login":"a_user@cms.gov","email":"a_user@cms.gov","LOA":"3"},"credentials":{"password":{},"emails":[{"value":"a_user@cms.gov","status":"VERIFIED","type":"PRIMARY"},{"value":"a_user@cms.gov","status":"VERIFIED","type":"SECONDARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123"}}}]`)
	})

	o := NewOktaMFA(client)
	foundUserId, err := o.getUser(searchString, trackingId)
	if err == nil {
		s.FailNow("getUser() should fail unless status=ACTIVE")
	}
	assert.Contains(s.T(), err.Error(), "active")
	assert.Equal(s.T(), "", foundUserId)
}

func (s *OTestSuite) TestGetUserMultipleUsers() {
	trackingId := uuid.NewRandom().String()
	searchString := "a_user"
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		return testHttpResponse(200, `[{"id":"def456","status":"ACTIVE","created":"2019-06-04T13:21:06.000Z","activated":"2019-06-04T13:21:07.000Z","statusChanged":"2019-06-04T13:21:07.000Z","lastLogin":null,"lastUpdated":"2019-06-04T13:21:07.000Z","passwordChanged":"2019-06-04T13:21:07.000Z","profile":{"firstName":"Test2","lastName":"User","mobilePhone":null,"secondEmail":"","login":"bcda_user1","email":"bcda_user1@cms.gov"},"credentials":{"password":{},"emails":[{"value":"bcda_user1@cms.gov","status":"VERIFIED","type":"PRIMARY"},{"value":"","status":"VERIFIED","type":"SECONDARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/def456"}}},{"id":"ghi789","status":"STAGED","created":"2019-06-04T13:22:55.000Z","activated":null,"statusChanged":null,"lastLogin":null,"lastUpdated":"2019-06-04T16:34:21.000Z","passwordChanged":null,"profile":{"firstName":"Test3","lastName":"User","aco_ids":["A0000","A0001"],"mobilePhone":null,"addressType":"Select Type...","secondEmail":null,"login":"bcda_user3@cms.gov","email":"bcda_user3@cms.gov","LOA":"Select Level..."},"credentials":{"emails":[{"value":"bcda_user3@cms.gov","status":"VERIFIED","type":"PRIMARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/ghi789"}}}]`)
	})

	o := NewOktaMFA(client)
	foundUserId, err := o.getUser(searchString, trackingId)
	if err == nil {
		s.FailNow("getUser() should fail unless a single user matches the search string")
	}
	assert.Contains(s.T(), err.Error(), "multiple")
	assert.Equal(s.T(), "", foundUserId)
}

func (s *OTestSuite) TestGetUserNoUsers() {
	trackingId := uuid.NewRandom().String()
	searchString := "no_match_expected"
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		return testHttpResponse(200, `[]`)
	})

	o := NewOktaMFA(client)
	foundUserId, err := o.getUser(searchString, trackingId)
	if err == nil {
		s.FailNow("getUser() should fail unless a user matches the search string")
	}
	assert.Contains(s.T(), err.Error(), "not found")
	assert.Equal(s.T(), "", foundUserId)
}

func (s *OTestSuite) TestGetUserBadToken() {
	trackingId := uuid.NewRandom().String()
	searchString := "no_match_expected"
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		return testHttpResponse(401, `{"errorCode":"E0000011","errorSummary":"Invalid token provided","errorLink":"E0000011","errorId":"oae3iIXhkQVQ2izGNwhnR47JQ","errorCauses":[]}`)
	})

	o := NewOktaMFA(client)
	foundUserId, err := o.getUser(searchString, trackingId)
	assert.NotNil(s.T(), err)
	assert.Contains(s.T(), err.Error(), "Invalid token provided")
	assert.Empty(s.T(), foundUserId)
}

func (s *OTestSuite) TestGetUserFactorSuccess() {
	trackingId := uuid.NewRandom().String()
	userId := "abc123"
	factorType := "SMS"
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		assert.Equal(s.T(), req.URL.String(), okta.OktaBaseUrl+"/api/v1/users/"+userId+"/factors")
		return testHttpResponse(200, `[{"id":"123abc","factorType":"call","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-06-05T14:13:57.000Z","lastUpdated":"2019-06-05T14:13:57.000Z","profile":{"phoneNumber":"+15555555555"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123def","factorType":"email","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","profile":{"email":"a_user@cms.gov"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123def","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123def/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123ghi","factorType":"sms","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-06-05T14:10:19.000Z","lastUpdated":"2019-06-05T14:10:19.000Z","profile":{"phoneNumber":"+15555555555"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123ghi","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123ghi/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123jkl","factorType":"token:software:totp","provider":"GOOGLE","vendorName":"GOOGLE","status":"ACTIVE","created":"2018-12-05T20:38:23.000Z","lastUpdated":"2018-12-05T20:38:47.000Z","profile":{"credentialId":"a_user@cms.gov"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123jkl","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123jkl/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123mno","factorType":"push","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-01-03T18:18:52.000Z","lastUpdated":"2019-01-03T18:19:04.000Z","profile":{"credentialId":"a_user@cms.gov","deviceType":"SmartPhone_IPhone","keys":[{"kty":"PKIX","use":"sig","kid":"default","x5c":["MIIBI..."]}],"name":"A User’s iPhone","platform":"IOS","version":"12.1.2"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123pqr","factorType":"token:software:totp","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-01-03T18:18:52.000Z","lastUpdated":"2019-01-03T18:19:04.000Z","profile":{"credentialId":"a_user@cms.gov"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123pqr","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123pqr/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}}]`)
	})

	o := NewOktaMFA(client)
	factor, err := o.getUserFactor(userId, factorType, trackingId)
	assert.Nil(s.T(), err)
	if factor == nil {
		s.FailNow("getUserFactor() should successfully return a factor")
	} else {
		assert.Equal(s.T(), "123ghi", factor.Id)
		assert.Equal(s.T(), "sms", factor.Type)
	}
}

func (s *OTestSuite) TestGetUserFactorAllTypes() {
	trackingId := uuid.NewRandom().String()
	userId := "abc123"
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		return testHttpResponse(200, `[{"id":"123abc","factorType":"call","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-06-05T14:13:57.000Z","lastUpdated":"2019-06-05T14:13:57.000Z","profile":{"phoneNumber":"+15555555555"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123def","factorType":"email","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","profile":{"email":"a_user@cms.gov"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123def","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123def/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123ghi","factorType":"sms","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-06-05T14:10:19.000Z","lastUpdated":"2019-06-05T14:10:19.000Z","profile":{"phoneNumber":"+15555555555"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123ghi","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123ghi/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123jkl","factorType":"token:software:totp","provider":"GOOGLE","vendorName":"GOOGLE","status":"ACTIVE","created":"2018-12-05T20:38:23.000Z","lastUpdated":"2018-12-05T20:38:47.000Z","profile":{"credentialId":"a_user@cms.gov"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123jkl","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123jkl/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123mno","factorType":"push","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-01-03T18:18:52.000Z","lastUpdated":"2019-01-03T18:19:04.000Z","profile":{"credentialId":"a_user@cms.gov","deviceType":"SmartPhone_IPhone","keys":[{"kty":"PKIX","use":"sig","kid":"default","x5c":["MIIBI..."]}],"name":"A User’s iPhone","platform":"IOS","version":"12.1.2"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123pqr","factorType":"token:software:totp","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-01-03T18:18:52.000Z","lastUpdated":"2019-01-03T18:19:04.000Z","profile":{"credentialId":"a_user@cms.gov"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123pqr","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123pqr/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}}]`)
	})
	o := NewOktaMFA(client)

	factor, err := o.getUserFactor(userId, "Call", trackingId)
	assert.Nil(s.T(), err)
	if factor == nil {
		s.FailNow("getUserFactor() should successfully return a factor")
	} else {
		assert.Equal(s.T(), "123abc", factor.Id)
		assert.Equal(s.T(), "call", factor.Type)
	}

	factor, err = o.getUserFactor(userId, "Email", trackingId)
	assert.Nil(s.T(), err)
	if factor == nil {
		s.FailNow("getUserFactor() should successfully return a factor")
	} else {
		assert.Equal(s.T(), "123def", factor.Id)
		assert.Equal(s.T(), "email", factor.Type)
	}

	factor, err = o.getUserFactor(userId, "Google TOTP", trackingId)
	assert.Nil(s.T(), err)
	if factor == nil {
		s.FailNow("getUserFactor() should successfully return a factor")
	} else {
		assert.Equal(s.T(), "123jkl", factor.Id)
		assert.Equal(s.T(), "token:software:totp", factor.Type)
		assert.Equal(s.T(), "GOOGLE", factor.Provider)
	}

	factor, err = o.getUserFactor(userId, "OKTA TOTP", trackingId)
	assert.Nil(s.T(), err)
	if factor == nil {
		s.FailNow("getUserFactor() should successfully return a factor")
	} else {
		assert.Equal(s.T(), "123pqr", factor.Id)
		assert.Equal(s.T(), "token:software:totp", factor.Type)
		assert.Equal(s.T(), "OKTA", factor.Provider)
	}

	factor, err = o.getUserFactor(userId, "Push", trackingId)
	assert.Nil(s.T(), err)
	if factor == nil {
		s.FailNow("getUserFactor() should successfully return a factor")
	} else {
		assert.Equal(s.T(), "123mno", factor.Id)
		assert.Equal(s.T(), "push", factor.Type)
	}
}

func (s *OTestSuite) TestGetUserFactorInactive() {
	trackingId := uuid.NewRandom().String()
	userId := "abc123"
	factorType := "Call"
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		assert.Equal(s.T(), req.URL.String(), okta.OktaBaseUrl+"/api/v1/users/"+userId+"/factors")
		return testHttpResponse(200, `[{"id":"123abc","factorType":"call","provider":"OKTA","vendorName":"OKTA","status":"PENDING","created":"2019-06-05T14:13:57.000Z","lastUpdated":"2019-06-05T14:13:57.000Z","profile":{"phoneNumber":"+15555555555"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123def","factorType":"email","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","profile":{"email":"a_user@cms.gov"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123def","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123def/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123ghi","factorType":"sms","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-06-05T14:10:19.000Z","lastUpdated":"2019-06-05T14:10:19.000Z","profile":{"phoneNumber":"+15555555555"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123ghi","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123ghi/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123jkl","factorType":"token:software:totp","provider":"GOOGLE","vendorName":"GOOGLE","status":"ACTIVE","created":"2018-12-05T20:38:23.000Z","lastUpdated":"2018-12-05T20:38:47.000Z","profile":{"credentialId":"a_user@cms.gov"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123jkl","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123jkl/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123mno","factorType":"push","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-01-03T18:18:52.000Z","lastUpdated":"2019-01-03T18:19:04.000Z","profile":{"credentialId":"a_user@cms.gov","deviceType":"SmartPhone_IPhone","keys":[{"kty":"PKIX","use":"sig","kid":"default","x5c":["MIIBI..."]}],"name":"A User’s iPhone","platform":"IOS","version":"12.1.2"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123pqr","factorType":"token:software:totp","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-01-03T18:18:52.000Z","lastUpdated":"2019-01-03T18:19:04.000Z","profile":{"credentialId":"a_user@cms.gov"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123pqr","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123pqr/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}}]`)
	})

	o := NewOktaMFA(client)
	factor, err := o.getUserFactor(userId, factorType, trackingId)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), factor)
}

func (s *OTestSuite) TestGetUserFactorNotFound() {
	trackingId := uuid.NewRandom().String()
	userId := "abc123"
	factorType := "Call"
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		assert.Equal(s.T(), req.URL.String(), okta.OktaBaseUrl+"/api/v1/users/"+userId+"/factors")
		return testHttpResponse(200, `[{"id":"123def","factorType":"email","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","profile":{"email":"a_user@cms.gov"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123def","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123def/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123jkl","factorType":"token:software:totp","provider":"GOOGLE","vendorName":"GOOGLE","status":"ACTIVE","created":"2018-12-05T20:38:23.000Z","lastUpdated":"2018-12-05T20:38:47.000Z","profile":{"credentialId":"a_user@cms.gov"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123jkl","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123jkl/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123mno","factorType":"push","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-01-03T18:18:52.000Z","lastUpdated":"2019-01-03T18:19:04.000Z","profile":{"credentialId":"a_user@cms.gov","deviceType":"SmartPhone_IPhone","keys":[{"kty":"PKIX","use":"sig","kid":"default","x5c":["MIIBI..."]}],"name":"A User’s iPhone","platform":"IOS","version":"12.1.2"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}},{"id":"123pqr","factorType":"token:software:totp","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-01-03T18:18:52.000Z","lastUpdated":"2019-01-03T18:19:04.000Z","profile":{"credentialId":"a_user@cms.gov"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123pqr","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123pqr/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}}]`)
	})

	o := NewOktaMFA(client)
	factor, err := o.getUserFactor(userId, factorType, trackingId)
	assert.NotNil(s.T(), err)
	assert.Nil(s.T(), factor)
}

func (s *OTestSuite) TestGetUserFactorBadToken() {
	trackingId := uuid.NewRandom().String()
	userId := "abc123"
	factorType := "Call"
	client := okta.NewTestClient(func(req *http.Request) *http.Response {
		return testHttpResponse(401, `{"errorCode":"E0000011","errorSummary":"Invalid token provided","errorLink":"E0000011","errorId":"oae3iIXhkQVQ2izGNwhnR47JQ","errorCauses":[]}`)
	})

	o := NewOktaMFA(client)
	factor, err := o.getUserFactor(userId, factorType, trackingId)
	assert.NotNil(s.T(), err)
	assert.Contains(s.T(), err.Error(), "Invalid token provided")
	assert.Nil(s.T(), factor)
}

func (s *OTestSuite) TestGenerateOktaTransactionId() {
	transactionId, err := generateOktaTransactionId()
	assert.Nil(s.T(), err)
	assert.True(s.T(), strings.HasPrefix(transactionId, "v2mst."))
	assert.Equal(s.T(), 28, len(transactionId))
}

func (s *OTestSuite) TestParsePushTransactionMatch() {
	testUrl := "https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno/transactions/v2mst.WmiSGGkvQc6P-QUQ5Qy0jg"
	transactionId := parsePushTransaction(testUrl)
	assert.Equal(s.T(), "v2mst.WmiSGGkvQc6P-QUQ5Qy0jg", transactionId)
}

func (s *OTestSuite) TestParsePushTransactionNoMatch() {
	testUrl := "https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno"
	transactionId := parsePushTransaction(testUrl)
	assert.Equal(s.T(), "", transactionId)
}

func (s *OTestSuite) TestFormatFactorReturnFailedSMSRequest() {
	result := formatFactorReturn("SMS", &FactorReturn{})
	assert.NotEmpty(s.T(), result)
	assert.Equal(s.T(), "request_sent", result.Action)
	assert.Empty(s.T(), result.Transaction)
}

func (s *OTestSuite) TestFormatFactorReturnFailedPushRequest() {
	result := formatFactorReturn("Push", &FactorReturn{})
	assert.NotEmpty(s.T(), result)
	assert.Equal(s.T(), "request_sent", result.Action)
	assert.NotEmpty(s.T(), result.Transaction)
	assert.NotEqual(s.T(), "", result.Transaction.TransactionID)
}

func (s *OTestSuite) TestFormatFactorReturnSucceededSMSRequest() {
	factorReturn := FactorReturn{Action: "request_sent"}
	assert.NotEmpty(s.T(), factorReturn)
	assert.Equal(s.T(), "request_sent", factorReturn.Action)
	assert.Nil(s.T(), factorReturn.Transaction)
}

func (s *OTestSuite) TestFormatFactorReturnSucceededPushRequest() {
	transaction := Transaction{TransactionID: "any_id"}
	f := FactorReturn{Action: "request_sent", Transaction: &transaction}
	factorReturn := formatFactorReturn("Push", &f)
	assert.NotEmpty(s.T(), factorReturn)
	assert.Equal(s.T(), "request_sent", factorReturn.Action)
	assert.Equal(s.T(), "any_id", factorReturn.Transaction.TransactionID)
	assert.True(s.T(), factorReturn.Transaction.ExpiresAt.After(time.Now()))
}

func (s *OTestSuite) TestVerifyFactorChallengeInvalidFactor() {
	trackingId := uuid.NewRandom().String()
	o := NewOktaMFA(nil)
	success, oktaID, groupIDs := o.VerifyFactorChallenge("bcda_user@cms.gov", "badFactor", "badPasscode", trackingId)
	assert.False(s.T(), success)
	assert.Equal(s.T(), "", oktaID)
	assert.Len(s.T(), groupIDs, 0)
}

func (s *OTestSuite) TestVerifyFactorChallengeUserNotFound() {
	trackingId := uuid.NewRandom().String()
	responses := []TestResponse{
		newTestResponse(isGetUser(), 200, `[]`),
	}
	client := okta.NewTestClient(testHttpResponses(responses))
	o := NewOktaMFA(client)
	success, oktaID, groupIDs := o.VerifyFactorChallenge("bcda_user@cms.gov", "sms", "badPasscode", trackingId)
	assert.False(s.T(), success)
	assert.Equal(s.T(), "", oktaID)
	assert.Len(s.T(), groupIDs, 0)
}

func (s *OTestSuite) TestVerifyFactorChallengeFactorNotFound() {
	trackingId := uuid.NewRandom().String()
	responses := []TestResponse{
		newTestResponse(isGetUser(), 200, `[{"id":"abc123","status":"ACTIVE","created":"2018-12-05T19:48:17.000Z","activated":"2018-12-05T19:48:17.000Z","statusChanged":"2019-06-04T12:52:49.000Z","lastLogin":"2019-06-06T18:45:35.000Z","lastUpdated":"2019-06-04T12:52:49.000Z","passwordChanged":"2019-06-04T12:52:49.000Z","profile":{"firstName":"Test","lastName":"User","mobilePhone":null,"addressType":"Select Type...","secondEmail":"bcda_user@cms.gov","login":"a_user@cms.gov","email":"a_user@cms.gov","LOA":"3"},"credentials":{"password":{},"emails":[{"value":"a_user@cms.gov","status":"VERIFIED","type":"PRIMARY"},{"value":"a_user@cms.gov","status":"VERIFIED","type":"SECONDARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123"}}}]`),
		newTestResponse(isGetFactor(), 200, `[]`),
	}
	client := okta.NewTestClient(testHttpResponses(responses))
	o := NewOktaMFA(client)
	success, oktaID, groupIDs := o.VerifyFactorChallenge("bcda_user@cms.gov", "sms", "badPasscode", trackingId)
	assert.False(s.T(), success)
	assert.Equal(s.T(), "abc123", oktaID)
	assert.Len(s.T(), groupIDs, 0)
}

func (s *OTestSuite) TestVerifyFactorChallengePasscodeError() {
	trackingId := uuid.NewRandom().String()
	responses := []TestResponse{
		newTestResponse(isGetUser(), 200, `[{"id":"abc123","status":"ACTIVE","created":"2018-12-05T19:48:17.000Z","activated":"2018-12-05T19:48:17.000Z","statusChanged":"2019-06-04T12:52:49.000Z","lastLogin":"2019-06-06T18:45:35.000Z","lastUpdated":"2019-06-04T12:52:49.000Z","passwordChanged":"2019-06-04T12:52:49.000Z","profile":{"firstName":"Test","lastName":"User","mobilePhone":null,"addressType":"Select Type...","secondEmail":"bcda_user@cms.gov","login":"a_user@cms.gov","email":"a_user@cms.gov","LOA":"3"},"credentials":{"password":{},"emails":[{"value":"a_user@cms.gov","status":"VERIFIED","type":"PRIMARY"},{"value":"a_user@cms.gov","status":"VERIFIED","type":"SECONDARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123"}}}]`),
		newTestResponse(isGetFactor(), 200, `[{"id":"123abc","factorType":"call","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-06-05T14:13:57.000Z","lastUpdated":"2019-06-05T14:13:57.000Z","profile":{"phoneNumber":"+15555555555"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}}]`),
		newTestResponse(isPostFactorChallenge(), 400, `{"errorCode":"E0000001","errorSummary":"Api validation failed: authRequest","errorLink":"E0000001","errorId":"oaebM8KyzEVS5uMiImx4sHzGg","errorCauses":[{"errorSummary":"The 'username' and 'password' attributes are required in this context."}]}`),
	}
	client := okta.NewTestClient(testHttpResponses(responses))
	o := NewOktaMFA(client)
	success, oktaID, groupIDs := o.VerifyFactorChallenge("bcda_user@cms.gov", "call", "badPasscode", trackingId)
	assert.False(s.T(), success)
	assert.Equal(s.T(), "abc123", oktaID)
	assert.Len(s.T(), groupIDs, 0)
}

func (s *OTestSuite) TestVerifyFactorChallengeInvalidPasscode() {
	trackingId := uuid.NewRandom().String()
	responses := []TestResponse{
		newTestResponse(isGetUser(), 200, `[{"id":"abc123","status":"ACTIVE","created":"2018-12-05T19:48:17.000Z","activated":"2018-12-05T19:48:17.000Z","statusChanged":"2019-06-04T12:52:49.000Z","lastLogin":"2019-06-06T18:45:35.000Z","lastUpdated":"2019-06-04T12:52:49.000Z","passwordChanged":"2019-06-04T12:52:49.000Z","profile":{"firstName":"Test","lastName":"User","mobilePhone":null,"addressType":"Select Type...","secondEmail":"bcda_user@cms.gov","login":"a_user@cms.gov","email":"a_user@cms.gov","LOA":"3"},"credentials":{"password":{},"emails":[{"value":"a_user@cms.gov","status":"VERIFIED","type":"PRIMARY"},{"value":"a_user@cms.gov","status":"VERIFIED","type":"SECONDARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123"}}}]`),
		newTestResponse(isGetFactor(), 200, `[{"id":"123abc","factorType":"call","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-06-05T14:13:57.000Z","lastUpdated":"2019-06-05T14:13:57.000Z","profile":{"phoneNumber":"+15555555555"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}}]`),
		newTestResponse(isPostFactorChallenge(), 403, `{"errorCode":"E0000068","errorSummary":"Invalid Passcode/Answer","errorLink":"E0000068","errorId":"oaeZAX9ava1RYS8lWNksxtqeg","errorCauses":[{"errorSummary":"Your token doesn't match our records. Please try again."}]}`),
	}
	client := okta.NewTestClient(testHttpResponses(responses))
	o := NewOktaMFA(client)
	success, oktaID, groupIDs := o.VerifyFactorChallenge("bcda_user@cms.gov", "call", "badPasscode", trackingId)
	assert.False(s.T(), success)
	assert.Equal(s.T(), "abc123", oktaID)
	assert.Len(s.T(), groupIDs, 0)
}

func (s *OTestSuite) TestVerifyFactorChallengeSuccess() {
	trackingId := uuid.NewRandom().String()
	responses := []TestResponse{
		newTestResponse(isGetUser(), 200, `[{"id":"abc123","status":"ACTIVE","created":"2018-12-05T19:48:17.000Z","activated":"2018-12-05T19:48:17.000Z","statusChanged":"2019-06-04T12:52:49.000Z","lastLogin":"2019-06-06T18:45:35.000Z","lastUpdated":"2019-06-04T12:52:49.000Z","passwordChanged":"2019-06-04T12:52:49.000Z","profile":{"firstName":"Test","lastName":"User","mobilePhone":null,"addressType":"Select Type...","secondEmail":"bcda_user@cms.gov","login":"a_user@cms.gov","email":"a_user@cms.gov","LOA":"3"},"credentials":{"password":{},"emails":[{"value":"a_user@cms.gov","status":"VERIFIED","type":"PRIMARY"},{"value":"a_user@cms.gov","status":"VERIFIED","type":"SECONDARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123"}}}]`),
		newTestResponse(isGetFactor(), 200, `[{"id":"123abc","factorType":"call","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-06-05T14:13:57.000Z","lastUpdated":"2019-06-05T14:13:57.000Z","profile":{"phoneNumber":"+15555555555"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}}]`),
		newTestResponse(isPostFactorChallenge(), 200, `{"factorResult":"SUCCESS"}`),
	}
	client := okta.NewTestClient(testHttpResponses(responses))
	o := NewOktaMFA(client)
	success, oktaID, groupIDs := o.VerifyFactorChallenge("bcda_user@cms.gov", "call", "badPasscode", trackingId)
	assert.True(s.T(), success)
	assert.Equal(s.T(), "abc123", oktaID)
	assert.Len(s.T(), groupIDs, 0)
}

func (s *OTestSuite) TestVerifyPasswordSuccess() {
	trackingId := uuid.NewRandom().String()
	responses := []TestResponse{
		newTestResponse(isGetUser(), 200, `[{"id":"abc123","status":"ACTIVE","created":"2018-12-05T19:48:17.000Z","activated":"2018-12-05T19:48:17.000Z","statusChanged":"2019-06-04T12:52:49.000Z","lastLogin":"2019-06-06T18:45:35.000Z","lastUpdated":"2019-06-04T12:52:49.000Z","passwordChanged":"2019-06-04T12:52:49.000Z","profile":{"firstName":"Test","lastName":"User","mobilePhone":null,"addressType":"Select Type...","secondEmail":"bcda_user@cms.gov","login":"a_user@cms.gov","email":"a_user@cms.gov","LOA":"3"},"credentials":{"password":{},"emails":[{"value":"a_user@cms.gov","status":"VERIFIED","type":"PRIMARY"},{"value":"a_user@cms.gov","status":"VERIFIED","type":"SECONDARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123"}}}]`),
		newTestResponse(isPostPassword(), 200, `{"stateToken":"00zABCabc123-000","expiresAt":"2019-09-16T19:28:58.000Z","status":"MFA_REQUIRED","_embedded":{"user":{"id":"abc123","passwordChanged":"2019-07-23T20:03:32.000Z","profile":{"login":"bcda_user2@cms.gov","firstName":"ACO","lastName":"User2","locale":"en","timeZone":"America/Los_Angeles"}},"factors":[{"id":"123ghi","factorType":"sms","provider":"OKTA","vendorName":"OKTA","profile":{"phoneNumber":"+1 XXX-XXX-7922"},"_links":{"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/authn/factors/123ghi/verify","hints":{"allow":["POST"]}}}}],"policy":{"allowRememberDevice":true,"rememberDeviceLifetimeInMinutes":30,"rememberDeviceByDefault":false,"factorsPolicyInfo":{}}},"_links":{"cancel":{"href":"https://cms-sandbox.oktapreview.com/api/v1/authn/cancel","hints":{"allow":["POST"]}}}}`),
	}
	client := okta.NewTestClient(testHttpResponses(responses))
	o := NewOktaMFA(client)
	passwordReturn, oktaID, err := o.VerifyPassword("bcda_user@cms.gov", "not_a_password", trackingId)
	if err != nil || passwordReturn == nil {
		assert.FailNow(s.T(), "must have valid passwordReturn")
	}
	assert.True(s.T(), passwordReturn.Success)
	assert.Equal(s.T(), "abc123", oktaID)
}

func (s *OTestSuite) TestVerifyPasswordUserNotFound() {
	trackingId := uuid.NewRandom().String()
	responses := []TestResponse{
		newTestResponse(isGetUser(), 200, `[]`),
	}
	client := okta.NewTestClient(testHttpResponses(responses))
	o := NewOktaMFA(client)
	passwordReturn, oktaID, err := o.VerifyPassword("bcda_user@cms.gov", "not_a_password", trackingId)
	assert.NotNil(s.T(), err)
	assert.Empty(s.T(), passwordReturn)
	assert.Equal(s.T(), "", oktaID)
}

func (s *OTestSuite) TestVerifyPasswordInvalidRequest() {
	trackingId := uuid.NewRandom().String()
	responses := []TestResponse{
		newTestResponse(isGetUser(), 200, `[{"id":"abc123","status":"ACTIVE","created":"2018-12-05T19:48:17.000Z","activated":"2018-12-05T19:48:17.000Z","statusChanged":"2019-06-04T12:52:49.000Z","lastLogin":"2019-06-06T18:45:35.000Z","lastUpdated":"2019-06-04T12:52:49.000Z","passwordChanged":"2019-06-04T12:52:49.000Z","profile":{"firstName":"Test","lastName":"User","mobilePhone":null,"addressType":"Select Type...","secondEmail":"bcda_user@cms.gov","login":"a_user@cms.gov","email":"a_user@cms.gov","LOA":"3"},"credentials":{"password":{},"emails":[{"value":"a_user@cms.gov","status":"VERIFIED","type":"PRIMARY"},{"value":"a_user@cms.gov","status":"VERIFIED","type":"SECONDARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123"}}}]`),
		newTestResponse(isPostPassword(), 200, `{"errorCode":"E0000001","errorSummary":"Api validation failed: authRequest","errorLink":"E0000001","errorId":"oaebM8KyzEVS5uMiImx4sHzGg","errorCauses":[{"errorSummary":"The 'username' and 'password' attributes are required in this context."}]}`),
	}
	client := okta.NewTestClient(testHttpResponses(responses))
	o := NewOktaMFA(client)
	passwordReturn, oktaID, err := o.VerifyPassword("bcda_user@cms.gov", "not_a_password", trackingId)
	assert.NotNil(s.T(), err)
	assert.Empty(s.T(), passwordReturn)
	assert.Equal(s.T(), "", oktaID)
}

func (s *OTestSuite) TestRequestFactorChallengeInvalidFactor() {
	trackingId := uuid.NewRandom().String()
	responses := []TestResponse{
		newTestResponse(isGetUser(), 200, `[{"id":"abc123","status":"ACTIVE","created":"2018-12-05T19:48:17.000Z","activated":"2018-12-05T19:48:17.000Z","statusChanged":"2019-06-04T12:52:49.000Z","lastLogin":"2019-06-06T18:45:35.000Z","lastUpdated":"2019-06-04T12:52:49.000Z","passwordChanged":"2019-06-04T12:52:49.000Z","profile":{"firstName":"Test","lastName":"User","mobilePhone":null,"addressType":"Select Type...","secondEmail":"bcda_user@cms.gov","login":"a_user@cms.gov","email":"a_user@cms.gov","LOA":"3"},"credentials":{"password":{},"emails":[{"value":"a_user@cms.gov","status":"VERIFIED","type":"PRIMARY"},{"value":"a_user@cms.gov","status":"VERIFIED","type":"SECONDARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123"}}}]`),
		newTestResponse(isGetFactor(), 200, `[{"id":"123abc","factorType":"call","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-06-05T14:13:57.000Z","lastUpdated":"2019-06-05T14:13:57.000Z","profile":{"phoneNumber":"+15555555555"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}}]`),
	}
	client := okta.NewTestClient(testHttpResponses(responses))
	o := NewOktaMFA(client)
	factorReturn, err := o.RequestFactorChallenge("bcda_user@cms.gov", "badFactor", trackingId)
	if err != nil {
		s.FailNow("RequestFactorChallenge should return an error for an invalid factor")
	}
	assert.NotEmpty(s.T(), factorReturn)
	assert.Equal(s.T(), "invalid_request", factorReturn.Action)
}

func (s *OTestSuite) TestRequestFactorChallengeCallFactor() {
	trackingId := uuid.NewRandom().String()
	responses := []TestResponse{
		newTestResponse(isGetUser(), 200, `[{"id":"abc123","status":"ACTIVE","created":"2018-12-05T19:48:17.000Z","activated":"2018-12-05T19:48:17.000Z","statusChanged":"2019-06-04T12:52:49.000Z","lastLogin":"2019-06-06T18:45:35.000Z","lastUpdated":"2019-06-04T12:52:49.000Z","passwordChanged":"2019-06-04T12:52:49.000Z","profile":{"firstName":"Test","lastName":"User","mobilePhone":null,"addressType":"Select Type...","secondEmail":"bcda_user@cms.gov","login":"a_user@cms.gov","email":"a_user@cms.gov","LOA":"3"},"credentials":{"password":{},"emails":[{"value":"a_user@cms.gov","status":"VERIFIED","type":"PRIMARY"},{"value":"a_user@cms.gov","status":"VERIFIED","type":"SECONDARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123"}}}]`),
		newTestResponse(isGetFactor(), 200, `[{"id":"123abc","factorType":"call","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-06-05T14:13:57.000Z","lastUpdated":"2019-06-05T14:13:57.000Z","profile":{"phoneNumber":"+15555555555"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}}]`),
		newTestResponse(isPostFactorChallenge(), 200, `{"factorResult":"CHALLENGE","_links":{"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc/verify","hints":{"allow":["POST"]}},"factor":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123abc","hints":{"allow":["GET","DELETE"]}}}}`),
	}
	client := okta.NewTestClient(testHttpResponses(responses))
	o := NewOktaMFA(client)
	factorReturn, err := o.RequestFactorChallenge("bcda_user@cms.gov", "Call", trackingId)
	if err != nil {
		s.FailNow("RequestFactorChallenge should not return an error for this combination of valid responses and valid factor")
	}
	assert.NotEmpty(s.T(), factorReturn)
	assert.Equal(s.T(), "request_sent", factorReturn.Action)
	assert.Empty(s.T(), factorReturn.Transaction)

	responseBody, err := json.Marshal(factorReturn)
	if err != nil {
		s.FailNow("RequestFactorChallenge should always be able to get valid JSON from the response")
	}
	assert.NotContains(s.T(), string(responseBody), "transaction")
}

func (s *OTestSuite) TestRequestFactorChallengePushFactor() {
	trackingId := uuid.NewRandom().String()
	responses := []TestResponse{
		newTestResponse(isGetUser(), 200, `[{"id":"abc123","status":"ACTIVE","created":"2018-12-05T19:48:17.000Z","activated":"2018-12-05T19:48:17.000Z","statusChanged":"2019-06-04T12:52:49.000Z","lastLogin":"2019-06-06T18:45:35.000Z","lastUpdated":"2019-06-04T12:52:49.000Z","passwordChanged":"2019-06-04T12:52:49.000Z","profile":{"firstName":"Test","lastName":"User","mobilePhone":null,"addressType":"Select Type...","secondEmail":"bcda_user@cms.gov","login":"a_user@cms.gov","email":"a_user@cms.gov","LOA":"3"},"credentials":{"password":{},"emails":[{"value":"a_user@cms.gov","status":"VERIFIED","type":"PRIMARY"},{"value":"a_user@cms.gov","status":"VERIFIED","type":"SECONDARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123"}}}]`),
		newTestResponse(isGetFactor(), 200, `[{"id":"123mno","factorType":"push","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-01-03T18:18:52.000Z","lastUpdated":"2019-01-03T18:19:04.000Z","profile":{"credentialId":"a_user@cms.gov","deviceType":"SmartPhone_IPhone","keys":[{"kty":"PKIX","use":"sig","kid":"default","x5c":["MIIBI..."]}],"name":"A User’s iPhone","platform":"IOS","version":"12.1.2"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}}]`),
		newTestResponse(isPostFactorChallenge(), 200, `{"factorResult":"WAITING","profile":{"credentialId":"bcda_user1@cms.gov","deviceType":"SmartPhone_IPhone","keys":[{"kty":"PKIX","use":"sig","kid":"default","x5c":["MIIBI..."]}],"name":"User’s iPhone","platform":"IOS","version":"12.1.2"},"expiresAt":"2019-07-12T14:21:30.000Z","_links":{"cancel":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno/transactions/v2mst.WmiSGGkvQc6P-QUQ5Qy0jg","hints":{"allow":["DELETE"]}},"poll":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno/transactions/v2mst.WmiSGGkvQc6P-QUQ5Qy0jg","hints":{"allow":["GET"]}}}}`),
	}
	client := okta.NewTestClient(testHttpResponses(responses))
	o := NewOktaMFA(client)
	factorReturn, err := o.RequestFactorChallenge("bcda_user@cms.gov", "Push", trackingId)
	if err != nil {
		s.FailNow("RequestFactorChallenge should not return an error for this combination of valid responses and valid factor")
	}
	assert.NotEmpty(s.T(), factorReturn)
	assert.Equal(s.T(), "request_sent", factorReturn.Action)
	assert.Equal(s.T(), "v2mst.WmiSGGkvQc6P-QUQ5Qy0jg", factorReturn.Transaction.TransactionID)

	responseBody, err := json.Marshal(factorReturn)
	if err != nil {
		s.FailNow("RequestFactorChallenge should always be able to get valid JSON from the response")
	}
	assert.Contains(s.T(), string(responseBody), "transaction")
}

func (s *OTestSuite) TestRequestFactorChallengeInvalidPasscode() {
	trackingId := uuid.NewRandom().String()
	responses := []TestResponse{
		newTestResponse(isGetUser(), 200, `[{"id":"abc123","status":"ACTIVE","created":"2018-12-05T19:48:17.000Z","activated":"2018-12-05T19:48:17.000Z","statusChanged":"2019-06-04T12:52:49.000Z","lastLogin":"2019-06-06T18:45:35.000Z","lastUpdated":"2019-06-04T12:52:49.000Z","passwordChanged":"2019-06-04T12:52:49.000Z","profile":{"firstName":"Test","lastName":"User","mobilePhone":null,"addressType":"Select Type...","secondEmail":"bcda_user@cms.gov","login":"a_user@cms.gov","email":"a_user@cms.gov","LOA":"3"},"credentials":{"password":{},"emails":[{"value":"a_user@cms.gov","status":"VERIFIED","type":"PRIMARY"},{"value":"a_user@cms.gov","status":"VERIFIED","type":"SECONDARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123"}}}]`),
		newTestResponse(isGetFactor(), 200, `[{"id":"123mno","factorType":"push","provider":"OKTA","vendorName":"OKTA","status":"ACTIVE","created":"2019-01-03T18:18:52.000Z","lastUpdated":"2019-01-03T18:19:04.000Z","profile":{"credentialId":"a_user@cms.gov","deviceType":"SmartPhone_IPhone","keys":[{"kty":"PKIX","use":"sig","kid":"default","x5c":["MIIBI..."]}],"name":"A User’s iPhone","platform":"IOS","version":"12.1.2"},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno","hints":{"allow":["GET","DELETE"]}},"verify":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123/factors/123mno/verify","hints":{"allow":["POST"]}},"user":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123","hints":{"allow":["GET"]}}}}]`),
		newTestResponse(isPostFactorChallenge(), 403, `{"errorCode":"E0000068","errorSummary":"Invalid Passcode/Answer","errorLink":"E0000068","errorId":"oaeZAX9ava1RYS8lWNksxtqeg","errorCauses":[{"errorSummary":"Your token doesn't match our records. Please try again."}]}`),
	}
	client := okta.NewTestClient(testHttpResponses(responses))
	o := NewOktaMFA(client)
	factorReturn, err := o.RequestFactorChallenge("bcda_user@cms.gov", "Push", trackingId)
	assert.NotNil(s.T(), err)
	assert.Equal(s.T(), "request_sent", factorReturn.Action)
}

func (s *OTestSuite) TestRequestFactorChallengeFactorNotFound() {
	trackingId := uuid.NewRandom().String()
	responses := []TestResponse{
		newTestResponse(isGetUser(), 200, `[{"id":"abc123","status":"ACTIVE","created":"2018-12-05T19:48:17.000Z","activated":"2018-12-05T19:48:17.000Z","statusChanged":"2019-06-04T12:52:49.000Z","lastLogin":"2019-06-06T18:45:35.000Z","lastUpdated":"2019-06-04T12:52:49.000Z","passwordChanged":"2019-06-04T12:52:49.000Z","profile":{"firstName":"Test","lastName":"User","mobilePhone":null,"addressType":"Select Type...","secondEmail":"bcda_user@cms.gov","login":"a_user@cms.gov","email":"a_user@cms.gov","LOA":"3"},"credentials":{"password":{},"emails":[{"value":"a_user@cms.gov","status":"VERIFIED","type":"PRIMARY"},{"value":"a_user@cms.gov","status":"VERIFIED","type":"SECONDARY"}],"provider":{"type":"OKTA","name":"OKTA"}},"_links":{"self":{"href":"https://cms-sandbox.oktapreview.com/api/v1/users/abc123"}}}]`),
		newTestResponse(isGetFactor(), 200, `[]`),
	}
	client := okta.NewTestClient(testHttpResponses(responses))
	o := NewOktaMFA(client)
	factorReturn, err := o.RequestFactorChallenge("bcda_user@cms.gov", "Push", trackingId)
	assert.NotNil(s.T(), err)
	assert.Contains(s.T(), err.Error(), "no active factor of requested type")
	assert.Equal(s.T(), "request_sent", factorReturn.Action)
}

func (s *OTestSuite) TestRequestFactorChallengeUserNotFound() {
	trackingId := uuid.NewRandom().String()
	responses := []TestResponse{
		newTestResponse(isGetUser(), 200, `[]`),
	}
	client := okta.NewTestClient(testHttpResponses(responses))
	o := NewOktaMFA(client)
	factorReturn, err := o.RequestFactorChallenge("bcda_user@cms.gov", "Push", trackingId)
	assert.NotNil(s.T(), err)
	assert.Contains(s.T(), err.Error(), "user not found")
	assert.Equal(s.T(), "request_sent", factorReturn.Action)
}

func (s *OTestSuite) TestVerifyFactorTransaction() {
	o := NewOktaMFA(nil)
	_, err := o.VerifyFactorTransaction("", "", "", "")
	if err == nil {
		assert.FailNow(s.T(), "error should be thrown")
	}
	assert.Contains(s.T(), err.Error(), "not yet implemented")
}

func TestOTestSuite(t *testing.T) {
	suite.Run(t, new(OTestSuite))
}

func isMatch(regex string, comparison string) bool {
	re := regexp.MustCompile(regex)
	return re.Match([]byte(comparison))
}

func testHttpResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       ioutil.NopCloser(bytes.NewBufferString(body)),
		Header:     make(http.Header),
	}
}

func testHttpResponses(responses []TestResponse) func(*http.Request) *http.Response {
	return func(req *http.Request) *http.Response {
		for _, resp := range responses {
			if resp.GiveAnswer(req) {
				return resp.Response
			}
		}
		return testHttpResponse(404, "Test request not found: "+req.URL.String())
	}
}

func newTestResponse(testFunc func(*http.Request) bool, code int, body string) TestResponse {
	response := testHttpResponse(code, body)
	return TestResponse{GiveAnswer: testFunc, Response: response}
}

func isPostFactorChallenge() func(*http.Request) bool {
	return func(req *http.Request) bool {
		return req.Method == "POST" && isMatch(`\/api\/v1\/users\/.*\/factors\/.*\/verify`, req.URL.String())
	}
}

func isGetUser() func(*http.Request) bool {
	return func(req *http.Request) bool {
		return req.Method == "GET" && isMatch(`\/api\/v1\/users\/\?q=`, req.URL.String())
	}
}

func isGetFactor() func(*http.Request) bool {
	return func(req *http.Request) bool {
		return req.Method == "GET" && isMatch(`\/api\/v1\/users\/.*\/factors`, req.URL.String())
	}
}

func isPostPassword() func(*http.Request) bool {
	return func(req *http.Request) bool {
		return req.Method == "POST" && isMatch(`\/api\/v1\/authn`, req.URL.String())
	}
}
