package mcpserver

// Streamable-HTTP transport (fork addition). The MCP endpoint is /mcp and
// always requires a static bearer token; /healthz is unauthenticated and
// reveals nothing beyond "the process is serving".

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/cheeseandcereal/proton-cal/pkg/config"
)

// EnvMCPToken is the environment variable holding the HTTP bearer token when
// no token file is given.
const EnvMCPToken = "PROTON_CAL_MCP_TOKEN"

// minTokenLen is the shortest bearer token the HTTP server accepts.
const minTokenLen = 32

// sessionTimeout closes MCP sessions idle for this long, so clients that
// vanish without a DELETE do not accumulate.
const sessionTimeout = 30 * time.Minute

// ReadToken returns the bearer token from tokenFile (surrounding whitespace
// trimmed) or, when tokenFile is empty, from $PROTON_CAL_MCP_TOKEN.
func ReadToken(tokenFile string) (string, error) {
	if tokenFile != "" {
		data, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("reading token file: %w", err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	if tok := strings.TrimSpace(os.Getenv(EnvMCPToken)); tok != "" {
		return tok, nil
	}
	return "", fmt.Errorf("no bearer token: pass --token-file or set %s", EnvMCPToken)
}

// newHTTPHandler builds the HTTP handler: /mcp behind the bearer token, and
// /healthz open. One MCP server (and one calendar service) is shared by all
// sessions.
func newHTTPHandler(s *server, disabled []string, token string) (http.Handler, error) {
	token = strings.TrimSpace(token)
	if len(token) < minTokenLen {
		return nil, fmt.Errorf("bearer token must be at least %d characters", minTokenLen)
	}
	srv, err := newMCPServer(s, disabled)
	if err != nil {
		return nil, err
	}
	want := []byte(token)
	verify := func(_ context.Context, got string, _ *http.Request) (*auth.TokenInfo, error) {
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{}, nil
	}
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{SessionTimeout: sessionTimeout},
	)

	mux := http.NewServeMux()
	mux.Handle("/mcp", auth.RequireBearerToken(verify, &auth.RequireBearerTokenOptions{AllowMissingExpiration: true})(mcpHandler))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux, nil
}

// RunHTTP serves MCP over streamable HTTP on addr until ctx is cancelled.
func RunHTTP(ctx context.Context, addr, token string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	h, err := newHTTPHandler(newServer(), cfg.DisabledTools, token)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	hs := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	fmt.Fprintf(os.Stderr, "proton-cal MCP: serving on http://%s/mcp\n", ln.Addr())

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := hs.Shutdown(shutdownCtx); err != nil {
			return err
		}
		if err := <-errc; !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}
