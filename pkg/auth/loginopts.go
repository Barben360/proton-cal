package auth

// Non-interactive login support (fork addition): credentials from the
// environment (e.g. `pass-cli run` resolving pass:// references), a CAPTCHA
// that can be solved between two runs, and quieter browser handling.

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/pkg/browser"
)

// Environment variables read by CredentialsFromEnv.
const (
	EnvUsername        = "PROTON_CAL_USERNAME"
	EnvPassword        = "PROTON_CAL_PASSWORD"
	EnvMailboxPassword = "PROTON_CAL_MAILBOX_PASSWORD"
	EnvTOTP            = "PROTON_CAL_TOTP" // a code, or an otpauth://totp/ URI
)

// maxCaptchaRounds bounds how many CAPTCHA challenges an interactive login
// walks through before giving up.
const maxCaptchaRounds = 3

// Credentials are login inputs supplied up front; empty fields are prompted.
type Credentials struct {
	Username        string
	Password        string
	MailboxPassword string
	TOTP            *TOTP
}

// LoginOptions tune LoginWith. The zero value is the upstream interactive flow.
type LoginOptions struct {
	Creds Credentials
	// NoBrowser prints the CAPTCHA URL without opening a browser.
	NoBrowser bool
	// NoWait returns a *CaptchaRequiredError on a CAPTCHA instead of waiting
	// for Enter, so the challenge can be solved before a second run.
	NoWait bool
	// CaptchaToken is a challenge token solved since a previous run.
	CaptchaToken string
}

// CaptchaRequiredError reports a CAPTCHA to solve at URL; rerun the login
// with Token as LoginOptions.CaptchaToken once it is solved.
type CaptchaRequiredError struct {
	URL   string
	Token string
}

func (e *CaptchaRequiredError) Error() string {
	return "CAPTCHA verification required: solve it at " + e.URL + ", then log in again with the challenge token"
}

// CredentialsFromEnv reads PROTON_CAL_USERNAME, _PASSWORD, _MAILBOX_PASSWORD
// and _TOTP. Unset variables leave their field empty (prompted later).
func CredentialsFromEnv(getenv func(string) string) (Credentials, error) {
	c := Credentials{
		Username:        getenv(EnvUsername),
		Password:        getenv(EnvPassword),
		MailboxPassword: getenv(EnvMailboxPassword),
	}
	if v := getenv(EnvTOTP); v != "" {
		tp, err := ParseTOTP(v)
		if err != nil {
			return Credentials{}, fmt.Errorf("%s: %w", EnvTOTP, err)
		}
		c.TOTP = tp
	}
	return c, nil
}

// Headless reports whether no graphical session is available to open a
// browser in (Linux without DISPLAY / WAYLAND_DISPLAY, e.g. a container).
func Headless() bool {
	return runtime.GOOS == "linux" && os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == ""
}

// silenceBrowser keeps the launched browser's own output (Chromium logs and
// the like) from burying the CAPTCHA prompt.
func silenceBrowser() {
	browser.Stdout, browser.Stderr = io.Discard, io.Discard
}

// Seams for the TOTP timing tests.
var (
	nowFunc   = time.Now
	sleepFunc = func(ctx context.Context, d time.Duration) error {
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return nil
		}
	}
)

// totpCode returns a code from the TOTP source, first waiting out a window
// about to expire.
func totpCode(ctx context.Context, tp *TOTP) (string, error) {
	if d := tp.Wait(nowFunc()); d > 0 {
		if err := sleepFunc(ctx, d); err != nil {
			return "", err
		}
	}
	return tp.Code(nowFunc()), nil
}
