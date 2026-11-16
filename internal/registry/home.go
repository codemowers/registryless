package registry

import (
	"html/template"
	"net/http"

	"github.com/codemowers/registryless/internal/ui"
)

var home = template.Must(template.New("home").Parse(`<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Registryless</title>
<style>
body{font:17px system-ui;max-width:760px;margin:8vh auto;padding:24px;color:#17212b;background:#f6f8fa}
h1{font-size:38px}pre{padding:20px;background:#17212b;color:#f0f5fa;white-space:pre-wrap;overflow-wrap:anywhere;border-radius:8px}
</style>
<h1>Push directly to your cluster.</h1>
<p>Registryless brings your Skaffold images straight to Kubernetes nodes.</p>
<p>Registry endpoint: <code>{{.Host}}</code></p>
{{if .Anonymous}}<p>Authentication is disabled. Push and pull without logging in.</p>
{{else}}<p>Sign in with your namespace's registry credentials using <code>docker login {{.Host}}</code>.</p>{{end}}
<pre>skaffold dev --default-repo {{.Host}}/&lt;namespace&gt;</pre>
<p><a href="/v2/">Registry API</a></p>
` + ui.Footer + `</html>`))

// Home serves the registry's landing page when browser OIDC is disabled.
func Home(host string, anonymous bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method == http.MethodHead {
			return
		}
		_ = home.Execute(w, struct {
			Host      string
			Anonymous bool
		}{host, anonymous})
	})
}
