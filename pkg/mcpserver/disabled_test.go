package mcpserver

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// connectWithDisabled builds the server through newMCPServer (the path Run
// uses) with the given disabled tools and returns a connected client.
func connectWithDisabled(t *testing.T, disabled []string) *mcp.ClientSession {
	t.Helper()
	srv, err := newMCPServer(failingServer(errors.New("unused")), disabled)
	if err != nil {
		t.Fatalf("newMCPServer: %v", err)
	}
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	srvSess, err := srv.Connect(ctx, st, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srvSess.Wait() })
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

func TestDisabledToolsAreNotListed(t *testing.T) {
	names := toolNames(t, connectWithDisabled(t, []string{"delete_calendar", "update_calendar"}))
	for _, gone := range []string{"delete_calendar", "update_calendar"} {
		if slices.Contains(names, gone) {
			t.Errorf("%s still listed: %v", gone, names)
		}
	}
	for _, kept := range []string{"list_events", "create_event", "delete_event"} {
		if !slices.Contains(names, kept) {
			t.Errorf("%s missing: %v", kept, names)
		}
	}
}

func TestDisabledToolCannotBeCalled(t *testing.T) {
	// list_calendars goes straight to the service bootstrap, so an enabled
	// call would surface the stub's "unused" error.
	cs := connectWithDisabled(t, []string{"list_calendars"})
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "list_calendars",
		Arguments: map[string]any{},
	})
	if err == nil && (res == nil || !res.IsError) {
		t.Fatal("calling a disabled tool succeeded")
	}
	// Must be refused as an unknown tool, not reach the handler (whose
	// bootstrap error "unused" would show up instead).
	msg := ""
	if err != nil {
		msg = err.Error()
	} else {
		msg = resultText(res)
	}
	if strings.Contains(msg, "unused") || !strings.Contains(msg, "list_calendars") {
		t.Fatalf("disabled tool reached its handler: %s", msg)
	}
}

func TestNoDisabledToolsKeepsEverything(t *testing.T) {
	names := toolNames(t, connectWithDisabled(t, nil))
	if !slices.Equal(names, allToolNames()) {
		t.Fatalf("tools = %v, want %v", names, allToolNames())
	}
}

func TestUnknownDisabledToolIsRejected(t *testing.T) {
	_, err := newMCPServer(failingServer(errors.New("unused")), []string{"delete_calendar", "delete_calender"})
	if err == nil {
		t.Fatal("typo in disabled_tools accepted")
	}
	if !strings.Contains(err.Error(), "delete_calender") {
		t.Fatalf("error does not name the unknown tool: %v", err)
	}
}

func resultText(res *mcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}
