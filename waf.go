package caddy_waf_plugin

import (
	"fmt"
	"net/http"

	"github.com/W0n9/t1k-sdk-go/pkg/gosnserver"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(CaddyWAF{})
}

// CaddyWAF implements an HTTP handler that writes the
// visitor's IP address to a file or stream.
type CaddyWAF struct {
	// The file or stream to write to. Can be "stdout"
	// or "stderr".
	// Output string `json:"output,omitempty"`
	SnserverAddr string `json:"snserver_addr,omitempty"` //snserver address

	Mode string `json:"mode,omitempty"` //Modes: Monitor, Protect

	Strategy string `json:"strategy,omitempty"` //Strategy: Request, RequestandResponse

	logger   *zap.Logger
	snserver *gosnserver.Server
}

// CaddyModule returns the Caddy module information.
func (CaddyWAF) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.waf_chaitin",
		New: func() caddy.Module { return new(CaddyWAF) },
	}
}

// Provision implements caddy.Provisioner.
func (m *CaddyWAF) Provision(ctx caddy.Context) error {

	m.logger = ctx.Logger(m) // g.logger is a *zap.Logger
	m.logger.Info("Provisioning WAF plugin instance")

	if m.SnserverAddr == "" {
		return fmt.Errorf("snserver address is required")
	}
	var snserver *gosnserver.Server
	var err error
	snserver, err = gosnserver.New(m.SnserverAddr)
	if err != nil {
		// fmt.Printf("error creating snserver: %s\n", err)
		return fmt.Errorf("error creating snserver: %s", err)
	}

	if m.Mode != "monitor" && m.Mode != "protect" {
		return fmt.Errorf("mode must be one of [monitor, protect]")
	}

	if m.Strategy != "request" && m.Strategy != "requestandresponse" {
		return fmt.Errorf("strategy must be one of [request, requestandresponse]")
	}

	m.snserver = snserver
	return nil
}

// Validate implements caddy.Validator.
func (m *CaddyWAF) Validate() error {

	m.logger.Info("waf plugin validate")
	return nil
}

// ServeHTTP implements caddyhttp.MiddlewareHandler.
func (m CaddyWAF) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// m.w.Write([]byte(r.RemoteAddr))

	result, err := m.snserver.DetectHttpRequest(r)
	if err != nil {
		// 无法连接snserver，跳出判断，直接放行
		fmt.Printf("error in detection: \n%+v\n", err)
		// return m.redirectIntercept(w) //拦截测试
	} else {
		if result.Blocked() {
			return m.redirectIntercept(w) //拦截
		}
	}
	return next.ServeHTTP(w, r) //下一层模块继续处理
}

func (m CaddyWAF) Start() error {
	m.logger.Info("App start.")
	return nil
}

func (m CaddyWAF) Stop() error {
	m.logger.Info("App stop.")
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*CaddyWAF)(nil)
	_ caddy.Validator             = (*CaddyWAF)(nil)
	_ caddyhttp.MiddlewareHandler = (*CaddyWAF)(nil)
	_ caddyfile.Unmarshaler       = (*CaddyWAF)(nil)
)
