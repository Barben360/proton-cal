// Package auth implements the interactive Proton login flow, session
// teardown, and key unlocking for proton-cal.
//
// Credential model (bridge-style): Login derives the salted key passphrase
// once (from the account/mailbox password and the primary key salt) and
// persists it in the session store alongside the session tokens. The account
// password itself is never persisted. Later commands restore the session and
// call UnlockKeys, which unlocks user/address keys from the stored salted
// passphrase without re-prompting.
//
// Scope note (live-verified): GET /core/v4/keys/salts requires the elevated
// "locked" scope, which a freshly logged-in or restored session may lack
// (HTTP 403, Proton code 9101). Gaining it requires a full SRP proof to
// PUT /core/v4/users/unlock, which go-proton-api does not implement; see
// unlockScope. The scope is dropped again (PUT /core/v4/users/lock) as soon
// as the salts have been fetched; see docs/overview.md for the full
// unlock/lock dance.
package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	proton "github.com/ProtonMail/go-proton-api"
	srp "github.com/ProtonMail/go-srp"
	"github.com/pkg/browser"

	"github.com/cheeseandcereal/proton-cal/pkg/config"
	"github.com/cheeseandcereal/proton-cal/pkg/papi"
)

// Login runs the interactive login flow and persists the session (tokens +
// salted key passphrase), returning the logged-in username for the caller to
// persist. Handles browser-based captcha and TOTP; FIDO2-only 2FA and
// email-code verification are unsupported.
func Login(ctx context.Context, prompter Prompter, cfg config.Config) (string, error) {
	return LoginWith(ctx, prompter, cfg, LoginOptions{})
}

// LoginWith is Login with credentials supplied up front and CAPTCHA options
// (fork addition); see LoginOptions.
func LoginWith(ctx context.Context, prompter Prompter, cfg config.Config, opts LoginOptions) (string, error) {
	configured := cfg.Username
	if opts.Creds.Username != "" {
		configured = opts.Creds.Username
	}
	username, password, err := promptCredentials(prompter, configured, opts.Creds.Password)
	if err != nil {
		return "", err
	}

	m := papi.NewManager(cfg.EffectiveBaseURL())
	defer m.Close()

	pc, a, err := authenticateWith(ctx, m, prompter, username, password, opts)
	if err != nil {
		return "", err
	}
	defer pc.Close()

	// The key passphrase needs salts fetched with a persisted session.
	store, err := config.NewSessionStore()
	if err != nil {
		return "", fmt.Errorf("opening session store: %w", err)
	}
	sess := config.Session{
		UID:          a.UID,
		AccessToken:  a.AccessToken,
		RefreshToken: a.RefreshToken,
	}
	if err := store.Save(sess); err != nil {
		return "", fmt.Errorf("saving session: %w", err)
	}
	raw := papi.New(sess, store, cfg.EffectiveBaseURL())
	defer raw.Close()

	keyPassword, err := promptKeyPassword(prompter, a.PasswordMode, password, opts.Creds.MailboxPassword)
	if err != nil {
		return "", err
	}

	salts, err := fetchSalts(ctx, m, raw, username, password)
	if err != nil {
		return "", err
	}

	user, addrs, err := FetchKeyData(ctx, raw)
	if err != nil {
		return "", err
	}

	saltedKeyPass, err := deriveAndVerifyKeyPass(user, addrs, salts, keyPassword)
	if err != nil {
		return "", err
	}

	if err := store.SetKeyPass(sess.UID, saltedKeyPass); err != nil {
		return "", fmt.Errorf("saving key passphrase: %w", err)
	}

	prompter.Notify("Login successful. Session saved.")

	return username, nil
}

// promptCredentials returns the configured username (prompting only when
// unset) and the given password, else a freshly prompted one.
func promptCredentials(prompter Prompter, configured, given string) (username, password string, err error) {
	username = configured
	if username == "" {
		input, err := prompter.Prompt("Proton username/email")
		if err != nil {
			return "", "", fmt.Errorf("reading username: %w", err)
		}
		username = strings.TrimSpace(input)
		if username == "" {
			return "", "", errors.New("no username provided")
		}
	}

	if given != "" {
		return username, given, nil
	}
	password, err = prompter.PromptSecret("Password")
	if err != nil {
		return "", "", fmt.Errorf("reading password: %w", err)
	}
	if password == "" {
		return "", "", errors.New("no password provided")
	}
	return username, password, nil
}

// authenticate performs SRP login (with captcha fallback) and TOTP 2FA,
// returning an authenticated client.
func authenticate(ctx context.Context, m *proton.Manager, prompter Prompter, username, password string) (*proton.Client, proton.Auth, error) {
	return authenticateWith(ctx, m, prompter, username, password, LoginOptions{})
}

func authenticateWith(ctx context.Context, m *proton.Manager, prompter Prompter, username, password string, opts LoginOptions) (*proton.Client, proton.Auth, error) {
	var (
		pc  *proton.Client
		a   proton.Auth
		err error
	)
	if opts.CaptchaToken != "" {
		// Solved since a previous run: go straight to the verified retry.
		pc, a, err = m.NewClientWithLoginWithHVToken(ctx, username, []byte(password),
			&proton.APIHVDetails{Methods: []string{"captcha"}, Token: opts.CaptchaToken})
	} else {
		pc, a, err = m.NewClientWithLogin(ctx, username, []byte(password))
	}
	if err != nil {
		pc, a, err = loginWithHumanVerification(ctx, m, prompter, username, password, err, opts)
		if err != nil {
			return nil, proton.Auth{}, err
		}
	}

	pc.AddAuthHandler(func(rotated proton.Auth) {
		a.AccessToken = rotated.AccessToken
		a.RefreshToken = rotated.RefreshToken
	})

	// Two-factor authentication. TwoFA.Enabled is a bitmask: HasTOTP (1),
	// HasFIDO2 (2), HasFIDO2AndTOTP (3). Prefer TOTP when available.
	switch {
	case a.TwoFA.Enabled&proton.HasTOTP != 0:
		var code string
		var err error
		if opts.Creds.TOTP != nil {
			code, err = totpCode(ctx, opts.Creds.TOTP)
		} else {
			code, err = prompter.Prompt("2FA code")
		}
		if err != nil {
			pc.Close()
			return nil, proton.Auth{}, fmt.Errorf("reading 2FA code: %w", err)
		}
		if err := pc.Auth2FA(ctx, proton.Auth2FAReq{TwoFactorCode: strings.TrimSpace(code)}); err != nil {
			pc.Close()
			return nil, proton.Auth{}, fmt.Errorf("2FA verification failed: %w", err)
		}
	case a.TwoFA.Enabled&proton.HasFIDO2 != 0:
		pc.Close()
		return nil, proton.Auth{}, errors.New("this account requires FIDO2 two-factor authentication, which proton-cal does not support; enable TOTP at https://account.proton.me and retry")
	}
	return pc, a, nil
}

// promptKeyPassword returns the key-unlock password: the prompted mailbox
// password in two-password mode, else the login password.
func promptKeyPassword(prompter Prompter, mode proton.PasswordMode, loginPassword, given string) (string, error) {
	if mode != proton.TwoPasswordMode {
		return loginPassword, nil
	}
	if given != "" {
		return given, nil
	}
	keyPassword, err := prompter.PromptSecret("Mailbox password")
	if err != nil {
		return "", fmt.Errorf("reading mailbox password: %w", err)
	}
	if keyPassword == "" {
		return "", errors.New("no mailbox password provided")
	}
	return keyPassword, nil
}

// fetchSalts fetches the key salts. On insufficient scope it gains the
// "locked" scope (SRP proof to /core/v4/users/unlock), retries once, then
// drops the scope again.
func fetchSalts(ctx context.Context, m *proton.Manager, raw *papi.Client, username, password string) (proton.Salts, error) {
	var out struct{ KeySalts proton.Salts }
	fetch := func() error {
		if err := raw.Get(ctx, "/core/v4/keys/salts", nil, &out); err != nil {
			return fmt.Errorf("fetching key salts: %w", err)
		}
		return nil
	}
	err := fetch()
	if err == nil {
		return out.KeySalts, nil
	}
	if !isInsufficientScope(err) {
		return nil, err
	}
	if err := WithLockedScope(ctx, m, raw, username, password, fetch); err != nil {
		return nil, err
	}
	return out.KeySalts, nil
}

// WithLockedScope gains the "locked" scope using the login password, runs fn,
// then drops it. Cleanup is best effort except for session refresh failures.
func WithLockedScope(ctx context.Context, m *proton.Manager, raw *papi.Client, username, password string, fn func() error) (err error) {
	if err := unlockScope(ctx, m, raw, username, password); err != nil {
		return fmt.Errorf("unlocking session scope: %w", err)
	}
	defer func() {
		if lockErr := raw.Put(ctx, "/core/v4/users/lock", struct{}{}, nil); errors.Is(lockErr, papi.ErrRefresh) {
			err = errors.Join(err, fmt.Errorf("re-locking session scope: %w", lockErr))
		}
	}()
	return fn()
}

// deriveAndVerifyKeyPass derives the salted key passphrase from the key
// password and primary key salt, verifying it unlocks key material before use.
func deriveAndVerifyKeyPass(user proton.User, addrs []proton.Address, salts proton.Salts, keyPassword string) ([]byte, error) {
	primaryKeyID, err := primaryUserKeyID(user)
	if err != nil {
		return nil, err
	}
	saltedKeyPass, err := salts.SaltForKey([]byte(keyPassword), primaryKeyID)
	if err != nil {
		return nil, fmt.Errorf("deriving salted key passphrase: %w", err)
	}
	if len(saltedKeyPass) == 0 {
		return nil, errors.New("deriving salted key passphrase: empty result")
	}

	userKR, addrKRs, err := proton.Unlock(user, addrs, saltedKeyPass, nil)
	if err != nil {
		return nil, fmt.Errorf("verifying key unlock (wrong mailbox password?): %w", err)
	}
	if len(addrKRs) == 0 {
		return nil, errors.New("no address keys could be unlocked; calendar decryption would fail")
	}
	userKR.ClearPrivateParams()
	for _, kr := range addrKRs {
		kr.ClearPrivateParams()
	}
	return saltedKeyPass, nil
}

// Logout clears the local session and cache before best-effort API revocation.
// A missing session is not an error.
func Logout(ctx context.Context) error {
	store, err := config.NewSessionStore()
	if err != nil {
		return fmt.Errorf("opening session store: %w", err)
	}

	sess, err := store.Load()
	if err != nil && !errors.Is(err, config.ErrNoSession) {
		return fmt.Errorf("loading session: %w", err)
	}
	if err := store.Clear(sess.UID); err != nil {
		return fmt.Errorf("clearing session: %w", err)
	}
	if err := config.ClearCache(); err != nil {
		return fmt.Errorf("clearing cache: %w", err)
	}

	if sess.Valid() {
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("loading config: %w", err)
		}
		client := papi.New(sess, store, cfg.EffectiveBaseURL())
		// Best effort: the session may already be expired or revoked.
		_ = client.Delete(ctx, "/auth/v4", nil)
		client.Close()
	}

	return nil
}

var openBrowser = func(u string) error {
	silenceBrowser()
	return browser.OpenURL(u)
}

// loginWithHumanVerification walks the CAPTCHA challenge(s) of a login that
// failed with code 9001: show the URL (opening a browser unless disabled),
// wait for Enter, retry with the token; a retry answered with a new challenge
// (not solved yet, or expired) starts another round, up to maxCaptchaRounds.
// With opts.NoWait it returns a *CaptchaRequiredError instead of waiting.
func loginWithHumanVerification(ctx context.Context, m *proton.Manager, prompter Prompter, username, password string, loginErr error, opts LoginOptions) (*proton.Client, proton.Auth, error) {
	err := loginErr
	for round := 1; ; round++ {
		details, derr := captchaDetails(err)
		if derr != nil {
			return nil, proton.Auth{}, derr
		}
		// The standalone page records CAPTCHA completion against the challenge token.
		verifyURL := "https://verify.proton.me/?methods=captcha&token=" + url.QueryEscape(details.Token)
		if opts.NoWait {
			return nil, proton.Auth{}, &CaptchaRequiredError{URL: verifyURL, Token: details.Token}
		}
		if round > maxCaptchaRounds {
			return nil, proton.Auth{}, fmt.Errorf("CAPTCHA still not accepted after %d attempts: %w", maxCaptchaRounds, err)
		}
		if round > 1 {
			prompter.Notify("The CAPTCHA was not accepted (not solved yet, or expired). A new challenge follows.")
		}
		prompter.Notify("CAPTCHA verification required. Solve it at:\n  " + verifyURL)
		if !opts.NoBrowser {
			if berr := openBrowser(verifyURL); berr != nil {
				prompter.Notify("Could not open your browser automatically. Open the link above to continue.")
			}
		}
		if _, perr := prompter.Prompt("Press Enter after completing the CAPTCHA"); perr != nil {
			return nil, proton.Auth{}, fmt.Errorf("waiting for captcha verification: %w", perr)
		}

		details.Methods = []string{"captcha"}
		pc, a, lerr := m.NewClientWithLoginWithHVToken(ctx, username, []byte(password), details)
		if lerr == nil {
			return pc, a, nil
		}
		var apiErr *proton.APIError
		if !errors.As(lerr, &apiErr) || !apiErr.IsHVError() {
			return nil, proton.Auth{}, fmt.Errorf("login failed after captcha verification: %w", lerr)
		}
		err = lerr
	}
}

// captchaDetails extracts a CAPTCHA challenge from a login error, or explains
// why it cannot be handled.
func captchaDetails(loginErr error) (*proton.APIHVDetails, error) {
	var apiErr *proton.APIError
	if !errors.As(loginErr, &apiErr) || !apiErr.IsHVError() {
		return nil, fmt.Errorf("login failed: %w", loginErr)
	}
	var details proton.APIHVDetails
	if err := json.Unmarshal(apiErr.Details, &details); err != nil {
		return nil, fmt.Errorf("parsing human verification details: %w", err)
	}
	if !slices.Contains(details.Methods, "captcha") {
		return nil, fmt.Errorf(
			"no supported verification method available (methods: %s); try logging in at https://account.proton.me first, then retry",
			strings.Join(details.Methods, ", "),
		)
	}
	if details.Token == "" {
		return nil, errors.New("human verification response is missing a token")
	}
	return &details, nil
}

// isInsufficientScope reports whether the token lacks scope (Proton code
// 9101). Code-based only: a bare HTTP 403 can be a real permission problem and
// must not trigger the SRP unlock dance.
func isInsufficientScope(err error) bool {
	return papi.IsCode(err, papi.CodeInsufficientScope)
}

// unlockScope gains the "locked" scope via SRP proof of the LOGIN password to
// PUT /core/v4/users/unlock (raw papi client, since go-proton-api lacks this
// endpoint), verifying the server proof. Only exercised by live integration
// runs; the in-memory test server implements neither scope nor endpoint.
func unlockScope(ctx context.Context, m *proton.Manager, raw *papi.Client, username, password string) error {
	info, err := m.AuthInfo(ctx, proton.AuthInfoReq{Username: username})
	if err != nil {
		return fmt.Errorf("fetching auth info: %w", err)
	}

	srpAuth, err := srp.NewAuth(info.Version, username, []byte(password), info.Salt, info.Modulus, info.ServerEphemeral)
	if err != nil {
		return fmt.Errorf("preparing SRP auth: %w", err)
	}

	proofs, err := srpAuth.GenerateProofs(2048)
	if err != nil {
		return fmt.Errorf("generating SRP proofs: %w", err)
	}

	var out struct {
		Code        int
		ServerProof string
	}
	if err := raw.Put(ctx, "/core/v4/users/unlock", map[string]any{
		"ClientEphemeral": base64.StdEncoding.EncodeToString(proofs.ClientEphemeral),
		"ClientProof":     base64.StdEncoding.EncodeToString(proofs.ClientProof),
		"SRPSession":      info.SRPSession,
	}, &out); err != nil {
		return fmt.Errorf("PUT /core/v4/users/unlock: %w", err)
	}

	serverProof, err := base64.StdEncoding.DecodeString(out.ServerProof)
	if err != nil {
		return fmt.Errorf("decoding server proof: %w", err)
	}
	if !bytes.Equal(serverProof, proofs.ExpectedServerProof) {
		return errors.New("server proof mismatch on unlock: possible MITM or server misbehaviour")
	}
	return nil
}

// primaryUserKeyID returns the ID of the user key marked primary, falling
// back to the first key.
func primaryUserKeyID(user proton.User) (string, error) {
	if len(user.Keys) == 0 {
		return "", errors.New("user has no keys")
	}
	for _, key := range user.Keys {
		if key.Primary {
			return key.ID, nil
		}
	}
	return user.Keys[0].ID, nil
}
