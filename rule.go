package caddy_waf_plugin

import (
	"net/http"
	"text/template"
)

// redirectIntercept Intercept request
func (m *CaddyWAF) redirectIntercept(w http.ResponseWriter) error {
	var tpl *template.Template
	w.WriteHeader(http.StatusNotImplemented)
	tpl, _ = template.New("default_listing").Parse(defaultWafTemplate)
	return tpl.Execute(w, nil)
}
