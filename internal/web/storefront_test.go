package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicStorefrontAndAssets(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	handler := ws.BuildHandler()

	for _, tc := range []struct {
		path, contentType, marker string
	}{
		{"/store", "text/html; charset=utf-8", "Choose a plan that fits"},
		{"/css/store.css", "text/css; charset=utf-8", "--accent"},
		{"/js/store.js", "text/javascript; charset=utf-8", "/api/v2/store/auth/login"},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200; body=%s", tc.path, rec.Code, rec.Body.String())
			continue
		}
		if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, tc.contentType) {
			t.Errorf("GET %s content type = %q, want prefix %q", tc.path, got, tc.contentType)
		}
		if !strings.Contains(rec.Body.String(), tc.marker) {
			t.Errorf("GET %s body does not contain %q", tc.path, tc.marker)
		}
		if got := rec.Header().Get("X-Robots-Tag"); got != "noindex, nofollow" {
			t.Errorf("GET %s X-Robots-Tag = %q", tc.path, got)
		}
	}
}

func TestPublicStorefrontRejectsWritesToPage(t *testing.T) {
	ws, _, cleanup := setupTestWebServer(t)
	defer cleanup()
	req := httptest.NewRequest(http.MethodPost, "/store", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	ws.BuildHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST /store = %d, want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("POST /store Allow = %q, want GET, HEAD", got)
	}
}
