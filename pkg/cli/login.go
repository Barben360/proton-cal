package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cheeseandcereal/proton-cal/pkg/auth"
	"github.com/cheeseandcereal/proton-cal/pkg/config"
)

func newLoginCmd() *cobra.Command {
	var (
		noPrompt     bool
		noBrowser    bool
		captchaToken string
	)
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Authenticate with Proton and save the session",
		Long: `Authenticate with Proton and save the session.

Credentials are prompted for, unless given in the environment (e.g. by
` + "`pass-cli run`" + ` resolving pass:// references):

  PROTON_CAL_USERNAME          login username/email
  PROTON_CAL_PASSWORD          login password
  PROTON_CAL_MAILBOX_PASSWORD  second password (two-password accounts only)
  PROTON_CAL_TOTP              a 2FA code, or an otpauth://totp/ URI: the
                               code is then computed when needed (prefer it:
                               a code resolved in advance can expire)

A CAPTCHA, if Proton asks for one, needs a human. Interactively the URL is
shown (and opened in a browser unless --no-browser or no display), and the
login continues after Enter. With --no-prompt nothing is read from the
terminal: a CAPTCHA ends the run with the URL to solve and the
--captcha-token to rerun with.`,
		Args: requireArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load()
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}
			creds, err := auth.CredentialsFromEnv(os.Getenv)
			if err != nil {
				return err
			}
			prompter := auth.NewTerminalPrompter()
			if noPrompt {
				prompter = noPrompter{}
			}
			username, err := auth.LoginWith(cmd.Context(), prompter, cfg, auth.LoginOptions{
				Creds:        creds,
				NoBrowser:    noBrowser || auth.Headless(),
				NoWait:       noPrompt,
				CaptchaToken: captchaToken,
			})
			var cr *auth.CaptchaRequiredError
			if errors.As(err, &cr) {
				fmt.Fprintln(errWriter, captchaInstructions(cr))
				return errors.New("login needs a CAPTCHA")
			}
			if err != nil {
				return err
			}
			// Remember the username and, on first login, the detected timezone.
			cfg.Username = username
			if cfg.Timezone == "" {
				cfg.Timezone = config.DetectTimezone()
			}
			if err := config.Save(cfg); err != nil {
				return fmt.Errorf("saving config: %w", err)
			}
			fmt.Fprintln(humanOut(), "Logged in successfully.")
			return nil
		},
	}
	cmd.Flags().BoolVar(&noPrompt, "no-prompt", false, "never read from the terminal: missing credentials and CAPTCHAs fail the run")
	cmd.Flags().BoolVar(&noBrowser, "no-browser", false, "print the CAPTCHA URL without opening a browser")
	cmd.Flags().StringVar(&captchaToken, "captcha-token", "", "challenge token of a CAPTCHA solved since the previous login attempt")
	return cmd
}

// captchaInstructions tells a non-interactive caller how to finish the login.
func captchaInstructions(cr *auth.CaptchaRequiredError) string {
	return "Proton asks for a CAPTCHA.\n" +
		"  1. Solve it in any browser: " + cr.URL + "\n" +
		"  2. Then run the login again with: --captcha-token " + cr.Token
}

// noPrompter refuses every prompt, naming the variable to set instead.
type noPrompter struct{}

var promptEnv = map[string]string{
	"Proton username/email": auth.EnvUsername,
	"Password":              auth.EnvPassword,
	"Mailbox password":      auth.EnvMailboxPassword,
	"2FA code":              auth.EnvTOTP,
}

func (noPrompter) Prompt(label string) (string, error) {
	if env, ok := promptEnv[label]; ok {
		return "", fmt.Errorf("%s needed but --no-prompt is set: set %s", strings.ToLower(label), env)
	}
	return "", fmt.Errorf("%q needed but --no-prompt is set", label)
}
func (p noPrompter) PromptSecret(label string) (string, error) { return p.Prompt(label) }
func (noPrompter) Notify(msg string)                           { fmt.Fprintln(errWriter, msg) }

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Clear the saved session",
		Args:  requireArgs(cobra.NoArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := auth.Logout(cmd.Context()); err != nil {
				return err
			}
			fmt.Fprintln(humanOut(), "Session cleared.")
			return nil
		},
	}
}
