package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/cheeseandcereal/proton-cal/pkg/mcpserver"
)

// newMCPCmd registers the MCP server command, wired to pkg/mcpserver.
func newMCPCmd() *cobra.Command {
	var httpAddr, tokenFile string
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Run the MCP server (stdio, or streamable HTTP with --http)",
		Long: `Run the Model Context Protocol server.

The server speaks MCP (JSON-RPC) over stdio: stdout carries the protocol,
all diagnostics go to stderr. It exposes Proton Calendar tools
(list_calendars, list_events, create_event, update_event, delete_event)
so AI tools like Claude Code or opencode can read and write your calendar.

Requires a saved session: run ` + "`proton-cal login`" + ` first. The server
never prompts; without a session every tool call returns an error.

Example MCP client configuration (e.g. in an mcpServers section):

  {
    "mcpServers": {
      "proton-calendar": {
        "command": "proton-cal",
        "args": ["mcp"]
      }
    }
  }

With --http ADDR (e.g. :8080) the server instead speaks streamable HTTP on
ADDR: the MCP endpoint is /mcp and requires "Authorization: Bearer <token>",
the token (at least 32 characters) coming from --token-file or
$PROTON_CAL_MCP_TOKEN. GET /healthz answers 200 without a token.

Tools listed in disabled_tools (config.toml) are not exposed on either
transport.`,
		Args: requireArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if httpAddr == "" {
				if tokenFile != "" {
					return errors.New("--token-file only applies with --http")
				}
				return mcpserver.Run(cmd.Context())
			}
			token, err := mcpserver.ReadToken(tokenFile)
			if err != nil {
				return err
			}
			return mcpserver.RunHTTP(cmd.Context(), httpAddr, token)
		},
	}
	cmd.Flags().StringVar(&httpAddr, "http", "", "serve streamable HTTP on this address instead of stdio (e.g. :8080)")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "file holding the HTTP bearer token (default: $"+mcpserver.EnvMCPToken+")")
	return cmd
}
