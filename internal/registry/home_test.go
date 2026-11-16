package registry

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHomeWithoutOIDC(t *testing.T) {
	for _, anonymous := range []bool{true, false} {
		handler := Home("less.example.test", anonymous)
		rw := httptest.NewRecorder()
		handler.ServeHTTP(rw, httptest.NewRequest("GET", "/", nil))
		body := rw.Body.String()
		if rw.Code != 200 || !strings.Contains(body, "skaffold dev --default-repo less.example.test/") {
			t.Fatal("missing landing page", rw.Code)
		}
		if strings.Contains(body, "Authentication is disabled") != anonymous {
			t.Fatal("incorrect authentication instructions")
		}
		if strings.Contains(body, "/auth/login") {
			t.Fatal("offered disabled OIDC login")
		}
		if !strings.Contains(body, `href="https://github.com/codemowers/registryless"`) || !strings.Contains(body, "<svg") {
			t.Fatal("missing GitHub link or icon")
		}
		rw = httptest.NewRecorder()
		handler.ServeHTTP(rw, httptest.NewRequest("GET", "/unknown", nil))
		if rw.Code != 404 {
			t.Fatal("unknown path did not return 404")
		}
	}
}
