package registry

import (
	"net/http/httptest"
	"testing"
)

func TestAuthlessPublicAPIStillProtectsInternalTransfers(t *testing.T) {
	s := &Server{Authless: true}
	rw := httptest.NewRecorder()
	s.ServeHTTP(rw, httptest.NewRequest("GET", "http://registry.example/v2/", nil))
	if rw.Code != 200 || rw.Header().Get("WWW-Authenticate") != "" {
		t.Fatalf("anonymous registry probe: status %d", rw.Code)
	}
	for _, write := range []bool{false, true} {
		if !s.authorize(httptest.NewRecorder(), httptest.NewRequest("PUT", "/", nil), "demo/app", write) {
			t.Fatal("authless public operation rejected")
		}
	}
	rw = httptest.NewRecorder()
	s.ServeHTTP(rw, httptest.NewRequest("GET", "http://registry.example/internal/ready/sha256:abc", nil))
	if rw.Code != 403 && rw.Code != 400 {
		t.Fatalf("unsigned internal request: status %d", rw.Code)
	}
}
