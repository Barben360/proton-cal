package mcpserver

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const testToken = "0123456789abcdef0123456789abcdef" // 32 chars

// httpTestServer serves the full HTTP handler (auth + MCP + healthz).
func httpTestServer(t *testing.T, disabled []string) *httptest.Server {
	t.Helper()
	h, err := newHTTPHandler(failingServer(errors.New("unused")), disabled, testToken)
	if err != nil {
		t.Fatalf("newHTTPHandler: %v", err)
	}
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return ts
}

type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	if b.token != "" {
		r.Header.Set("Authorization", "Bearer "+b.token)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func connectHTTP(ctx context.Context, url, token string) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	return client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:             url + "/mcp",
		HTTPClient:           &http.Client{Transport: bearerTransport{token}},
		DisableStandaloneSSE: true,
	}, nil)
}

func TestHTTPServesToolsWithValidToken(t *testing.T) {
	ts := httpTestServer(t, []string{"delete_calendar"})
	cs, err := connectHTTP(context.Background(), ts.URL, testToken)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = cs.Close() }()
	names := toolNames(t, cs)
	if !strings.Contains(strings.Join(names, ","), "list_events") {
		t.Fatalf("list_events not served over HTTP: %v", names)
	}
	// disabled_tools applies to the HTTP transport too.
	for _, n := range names {
		if n == "delete_calendar" {
			t.Fatal("disabled tool served over HTTP")
		}
	}
}

func TestHTTPRejectsMissingOrWrongToken(t *testing.T) {
	ts := httpTestServer(t, nil)
	for name, token := range map[string]string{"missing": "", "wrong": strings.Repeat("x", 32), "prefix": testToken[:31]} {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
		})
	}
}

func TestHealthzNeedsNoToken(t *testing.T) {
	ts := httpTestServer(t, nil)
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
	}
}

func TestHTTPHandlerRefusesWeakToken(t *testing.T) {
	for name, token := range map[string]string{"empty": "", "short": "tooshort", "blank": strings.Repeat(" ", 40)} {
		t.Run(name, func(t *testing.T) {
			if _, err := newHTTPHandler(failingServer(errors.New("unused")), nil, token); err == nil {
				t.Fatalf("token %q accepted", token)
			}
		})
	}
}

func TestHTTPHandlerRejectsUnknownDisabledTool(t *testing.T) {
	if _, err := newHTTPHandler(failingServer(errors.New("unused")), []string{"nope"}, testToken); err == nil {
		t.Fatal("unknown disabled tool accepted over HTTP")
	}
}

func TestReadTokenFromFileTrimsNewline(t *testing.T) {
	t.Setenv(EnvMCPToken, "")
	p := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(p, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadToken(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != testToken {
		t.Fatalf("token = %q, want %q", got, testToken)
	}
}

func TestReadTokenFallsBackToEnv(t *testing.T) {
	t.Setenv(EnvMCPToken, testToken)
	got, err := ReadToken("")
	if err != nil {
		t.Fatal(err)
	}
	if got != testToken {
		t.Fatalf("token = %q, want env value", got)
	}
}

func TestReadTokenErrorsWithoutSource(t *testing.T) {
	t.Setenv(EnvMCPToken, "")
	if _, err := ReadToken(""); err == nil {
		t.Fatal("no token source accepted")
	}
	if _, err := ReadToken(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing token file accepted")
	}
}
