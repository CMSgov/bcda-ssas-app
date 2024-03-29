package service

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/CMSgov/bcda-ssas-app/ssas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	"gorm.io/gorm"
)

type APICommonTestSuite struct {
	suite.Suite
	db *gorm.DB
}

func (s *APICommonTestSuite) SetupSuite() {
	s.db = ssas.Connection
}

func (s *APICommonTestSuite) TestJSONError() {
	// JSON output is valid for simple strings
	w := httptest.NewRecorder()
	JSONError(w, http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), "unauthorized")
	resp := w.Result()
	body, err := io.ReadAll(resp.Body)
	assert.NoError(s.T(), err)
	assert.True(s.T(), json.Valid(body))
	assert.Equal(s.T(), `{"error":"Unauthorized","error_description":"unauthorized"}`, string(body))

	// JSON output is valid for strings that need to be escaped
	w = httptest.NewRecorder()
	JSONError(w, http.StatusInternalServerError, http.StatusText(http.StatusInternalServerError), `oh no, there's a database problem (and a backslash \)!: pq: duplicate key value violates unique constraint "groups_group_id_deleted_at_key"`)
	resp = w.Result()
	body, err = io.ReadAll(resp.Body)
	assert.NoError(s.T(), err)
	assert.True(s.T(), json.Valid(body))
	assert.Equal(s.T(), `{"error":"Internal Server Error","error_description":"oh no, there's a database problem (and a backslash \\)!: pq: duplicate key value violates unique constraint \"groups_group_id_deleted_at_key\""}`, string(body))
}

func TestAPICommonTestSuite(t *testing.T) {
	suite.Run(t, new(APICommonTestSuite))
}
