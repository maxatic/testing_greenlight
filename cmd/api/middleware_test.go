package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"greenlight.bcc/internal/assert"
)

func TestRecoverPanicMiddleware(t *testing.T) {
	// Create a new application instance
	app := newTestApplication(t)

	// Create a new request that will trigger a panic
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	recorder := httptest.NewRecorder()

	// Create a test handler that will panic
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("something went wrong")
	})

	// Wrap the handler with the middleware
	middleware := app.recoverPanic(handler)

	// Call the middleware
	middleware.ServeHTTP(recorder, req)

	// Check that the response status code is 500
	assert.Equal(t, http.StatusInternalServerError, recorder.Code)

	// // Check that the response body contains the error message
	// expectedBody := `{"error":"the server encountered a problem and could not process your request"}`
	// assert.Equal(t, expectedBody, recorder.Body.String())

	expectedJSON := `{"error":"the server encountered a problem and could not process your request"}`
	actualJSON := strings.TrimSpace(recorder.Body.String())

	if !json.Valid([]byte(actualJSON)) {
		t.Fatalf("invalid JSON response: %s", actualJSON)
	}

	var expected interface{}
	var actual interface{}
	if err := json.Unmarshal([]byte(expectedJSON), &expected); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(actualJSON), &actual); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("unexpected response body:\nexpected: %v\nactual: %v", expected, actual)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	app := newTestApplication(t)

	ts := newTestServer(t, app.routesTest())
	defer ts.Close()

	for i := 0; i < 4; i++ {

		t.Run("Valid", func(t *testing.T) {
			code, _, _ := ts.get(t, "/v1/movies")

			assert.Equal(t, code, http.StatusOK)
		})
	}

	code, _, _ := ts.get(t, "/v1/movies")
	assert.Equal(t, code, http.StatusTooManyRequests)
}

func TestRequireAuthenticated(t *testing.T) {
	app := newTestApplication(t)
	ts := newTestServer(t, app.routesTest())
	defer ts.Close()

	// users := []data.User{
	// 	{ID: 1, Name: "Ryan Gosling"},
	// 	{ID: 2, Name: "NOT Ryan Gosling"},
	// }

	tests := []struct {
		name     string
		wantCode int
		token    string
	}{
		{
			name:     "OK test",
			wantCode: http.StatusOK,
			token:    "Bearer BusinessManBusinessPlan123",
		},
		{
			name:     "Unauthorized",
			wantCode: http.StatusUnauthorized,
			token:    "Bearer f",
		},
		{
			name:     "Anonymous user test",
			wantCode: http.StatusUnauthorized,
			token:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, _ := ts.getWithAuth(t, "/testauth/v1/movies", tt.token)
			assert.Equal(t, code, tt.wantCode)
		})
	}
}

func TestRequireActivated(t *testing.T) {
	app := newTestApplication(t)
	ts := newTestServer(t, app.routesTest())
	defer ts.Close()

	tests := []struct {
		name     string
		wantCode int
		token    string
	}{
		{
			name:     "OK test",
			wantCode: http.StatusOK,
			token:    "Bearer BusinessManBusinessPlan123",
		},
		{
			name:     "Unauthorized",
			wantCode: http.StatusUnauthorized,
			token:    "Bearer f",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, _ := ts.getWithAuth(t, "/testactivated/v1/movies", tt.token)
			assert.Equal(t, code, tt.wantCode)
		})
	}
}

func TestRequirePermissions(t *testing.T) {
	app := newTestApplication(t)
	ts := newTestServer(t, app.routesTest())
	defer ts.Close()

	tests := []struct {
		name     string
		wantCode int
		token    string
	}{
		{
			name:     "OK test movies:read",
			wantCode: http.StatusOK,
			token:    "Bearer BusinessManBusinessPlan123",
		},
		{
			name:     "Forbidden request (not activated account)",
			wantCode: http.StatusForbidden,
			token:    "Bearer BusinessManBusinessPlanNOO",
		},
		{
			name:     "Forbidden request (no required permissions)",
			wantCode: http.StatusForbidden,
			token:    "Bearer BusinessManBusinessPlan000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, _ := ts.getWithAuth(t, "/testpermissions/v1/movies", tt.token)
			assert.Equal(t, code, tt.wantCode)
		})
	}
}

func TestAuthenticateMiddleware(t *testing.T) {
	app := newTestApplication(t)
	ts := newTestServer(t, app.routesTest())
	defer ts.Close()

	// update movie fields
	tests := []struct {
		name     string
		url      string
		wantCode int
		token    string
		Title    string   `json:"title"`
		Year     int32    `json:"year"`
		Genres   []string `json:"genres"`
		Runtime  string   `json:"runtime"`
	}{
		{
			name:     "Anonym",
			url:      "/v1/movies/1",
			wantCode: http.StatusOK,
			token:    "",
			Title:    "Updated Title",
			Runtime:  "105 mins",
		},
		{
			name:     "No Prefix Token",
			url:      "/v1/movies/1",
			wantCode: http.StatusUnauthorized,
			token:    "wasd",
			Title:    "Updated Title",
			Runtime:  "105 mins",
		},
		{
			name:     "Invalid Token",
			url:      "/v1/movies/1",
			wantCode: http.StatusUnauthorized,
			token:    "Bearer wasd",
			Title:    "Updated Title",
			Runtime:  "105 mins",
		}, {
			name:     "OK Token",
			url:      "/v1/movies/1",
			wantCode: http.StatusOK,
			token:    "Bearer BusinessManBusinessPlan123",
			Title:    "Updated Title",
			Runtime:  "105 mins",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputData := struct {
				Title   string   `json:"title,omitempty"`
				Year    int32    `json:"year,omitempty"`
				Runtime string   `json:"runtime,omitempty"`
				Genres  []string `json:"genres,omitempty"`
			}{
				Title:   tt.Title,
				Year:    tt.Year,
				Genres:  tt.Genres,
				Runtime: tt.Runtime,
			}

			b, err := json.Marshal(&inputData)
			if err != nil {
				t.Fatal("wrong input data")
			}

			code, _, _ := ts.patchForAuth(t, tt.url, b, tt.token)

			assert.Equal(t, code, tt.wantCode)
		})
	}
}

// func TestEnableCORS(t *testing.T) {
// 	// Create a new application instance
// 	app := newTestApplication(t)

// 	ts := newTestServer(t, app.routesTest())
// 	defer ts.Close()

// 	// Create a GET request with an Origin header that matches one of the trusted origins
// 	req, err := http.NewRequest("GET", ts.URL, nil)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	req.Header.Set("Origin", "http://example.com")

// 	tests := []struct {
// 		name     string
// 		url      string
// 		wantCode int
// 		origin   string
// 	}{
// 		{
// 			name:     "OK",
// 			url:      "/v1/movies",
// 			wantCode: http.StatusOK,
// 			origin:   "http://example.com",
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			code, headers, _ := ts.getWithOrigin(t, tt.url, tt.origin)
// 			assert.Equal(t, code, tt.wantCode)

// 			assert.Equal(t, headers.Get("Access-Control-Allow-Origin"), "http://example.com")

// 		})
// 	}

	// // Verify that the Access-Control-Allow-Origin header is set correctly
	// assert.Equal(t, resp.Header.Get("Access-Control-Allow-Origin"), "http://example.com")

	// // Verify that the Access-Control-Allow-Methods header is set correctly for a preflight request
	// req, err = http.NewRequest("OPTIONS", server.URL, nil)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// req.Header.Set("Origin", "http://example.com")
	// req.Header.Set("Access-Control-Request-Method", "PUT")

	// // Send the preflight request
	// resp, err = client.Do(req)
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// defer resp.Body.Close()

	// // Verify that the Access-Control-Allow-Methods header is set correctly
	// assert.Equal(t, resp.Header.Get("Access-Control-Allow-Methods"), "OPTIONS, PUT, PATCH, DELETE")

	// // Verify that the Access-Control-Allow-Headers header is set correctly
	// assert.Equal(t, resp.Header.Get("Access-Control-Allow-Headers"), "Authorization, Content-Type")

	// // Verify that the preflight request returns a 200 OK status code
	// assert.Equal(t, resp.StatusCode, http.StatusOK)
// }

// func TestMyHandler(t *testing.T) {
// 	app := newTestApplication(t)
// }
