package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-proton-api/server"
	"github.com/pkg/browser"

	"github.com/cheeseandcereal/proton-cal/pkg/config"
	"github.com/cheeseandcereal/proton-cal/pkg/papi"
)

// front is a proxy in front of the in-memory Proton server that can answer
// /auth/v4 with CAPTCHA challenges and pretend the account has TOTP 2FA.
type front struct {
	mu       sync.Mutex
	attempts int
	hvTokens []string // HV token header seen on each /auth/v4 attempt
	codes    []string // 2FA codes received
	// challenge decides, per attempt (1-based), whether to answer with a
	// CAPTCHA challenge and which challenge token to hand out.
	challenge func(attempt int, hvToken string) (token string, ok bool)
	twoFA     bool
	url       string
}

func newFront(t *testing.T, f *front) *front {
	t.Helper()
	backend := server.New(server.WithTLS(false))
	t.Cleanup(backend.Close)
	if _, _, err := backend.CreateUser(testUser, []byte(testPass)); err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(backend.GetHostURL())
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ModifyResponse = func(resp *http.Response) error {
		if !f.twoFA || resp.Request.Method != http.MethodPost || resp.Request.URL.Path != "/auth/v4" || resp.StatusCode != http.StatusOK {
			return nil
		}
		var body map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			return err
		}
		body["2FA"] = map[string]any{"Enabled": 1}
		data, _ := json.Marshal(body)
		resp.Body = io.NopCloser(bytes.NewReader(data))
		resp.ContentLength = int64(len(data))
		resp.Header.Del("Content-Length")
		return nil
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/auth/v4":
			f.mu.Lock()
			f.attempts++
			attempt := f.attempts
			tok := r.Header.Get("x-pm-human-verification-token")
			f.hvTokens = append(f.hvTokens, tok)
			f.mu.Unlock()
			if f.challenge != nil {
				if ct, ok := f.challenge(attempt, tok); ok {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnprocessableEntity)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"Code": 9001, "Error": "Human verification required",
						"Details": map[string]any{"HumanVerificationMethods": []string{"captcha"}, "HumanVerificationToken": ct},
					})
					return
				}
			}
		case r.Method == http.MethodPost && r.URL.Path == "/auth/v4/2fa":
			var req struct{ TwoFactorCode string }
			_ = json.NewDecoder(r.Body).Decode(&req)
			f.mu.Lock()
			f.codes = append(f.codes, req.TwoFactorCode)
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"Code": 1000, "Scopes": []string{"full"}})
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	f.url = ts.URL
	return f
}

func noBrowser(t *testing.T) *bool {
	t.Helper()
	opened := false
	orig := openBrowser
	openBrowser = func(string) error { opened = true; return nil }
	t.Cleanup(func() { openBrowser = orig })
	return &opened
}

// silentPrompter fails the test on any prompt.
func silentPrompter(t *testing.T) *scriptPrompter {
	return &scriptPrompter{t: t, answers: map[string]string{}}
}

func TestLoginWithEnvCredentialsNeverPrompts(t *testing.T) {
	startServer(t)
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	username, err := LoginWith(context.Background(), silentPrompter(t), cfg, LoginOptions{
		Creds: Credentials{Username: testUser, Password: testPass},
	})
	if err != nil {
		t.Fatalf("LoginWith: %v", err)
	}
	if username != testUser {
		t.Fatalf("username = %q", username)
	}
}

func TestCredentialsFromEnv(t *testing.T) {
	env := map[string]string{
		EnvUsername: "me@proton.me", EnvPassword: "pw", EnvMailboxPassword: "mbx",
		EnvTOTP: "otpauth://totp/x?secret=" + b32("12345678901234567890"),
	}
	c, err := CredentialsFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if c.Username != "me@proton.me" || c.Password != "pw" || c.MailboxPassword != "mbx" || c.TOTP == nil {
		t.Fatalf("creds = %+v", c)
	}
	if got := c.TOTP.Code(time.Unix(59, 0)); got != "287082" {
		t.Fatalf("TOTP from env = %s", got)
	}

	empty, err := CredentialsFromEnv(func(string) string { return "" })
	if err != nil || empty.Username != "" || empty.Password != "" || empty.TOTP != nil {
		t.Fatalf("empty env: %+v, %v", empty, err)
	}

	env[EnvTOTP] = "not-a-code"
	if _, err := CredentialsFromEnv(func(k string) string { return env[k] }); err == nil || !strings.Contains(err.Error(), EnvTOTP) {
		t.Fatalf("bad TOTP must be refused naming %s, got %v", EnvTOTP, err)
	}
}

func TestCaptchaWithoutWaitingReturnsTheChallenge(t *testing.T) {
	opened := noBrowser(t)
	f := newFront(t, &front{challenge: func(int, string) (string, bool) { return "tok-1", true }})
	m := papi.NewManager(f.url)
	t.Cleanup(m.Close)

	_, _, err := authenticateWith(t.Context(), m, silentPrompter(t), testUser, testPass, LoginOptions{NoWait: true, NoBrowser: true})
	var cr *CaptchaRequiredError
	if !errors.As(err, &cr) {
		t.Fatalf("want *CaptchaRequiredError, got %v", err)
	}
	if cr.Token != "tok-1" || !strings.Contains(cr.URL, "token=tok-1") {
		t.Fatalf("challenge = %+v", cr)
	}
	if *opened {
		t.Error("browser opened despite NoBrowser")
	}
	if f.attempts != 1 {
		t.Errorf("attempts = %d, want 1 (no retry without a solved CAPTCHA)", f.attempts)
	}
}

func TestCaptchaTokenFromPreviousRunIsUsedRightAway(t *testing.T) {
	noBrowser(t)
	// The server only lets the login through with the solved token.
	f := newFront(t, &front{challenge: func(_ int, tok string) (string, bool) { return "tok-new", tok != "tok-solved" }})
	m := papi.NewManager(f.url)
	t.Cleanup(m.Close)

	pc, _, err := authenticateWith(t.Context(), m, silentPrompter(t), testUser, testPass, LoginOptions{NoWait: true, CaptchaToken: "tok-solved"})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	pc.Close()
	if len(f.hvTokens) != 1 || f.hvTokens[0] != "tok-solved" {
		t.Fatalf("auth attempts carried HV tokens %q, want exactly one with tok-solved", f.hvTokens)
	}
}

func TestInteractiveCaptchaAsksAgainUntilAccepted(t *testing.T) {
	opened := noBrowser(t)
	// Attempt 1: challenge A. Attempt 2 (token A, not solved): challenge B.
	// Attempt 3 (token B): through.
	f := newFront(t, &front{challenge: func(attempt int, _ string) (string, bool) {
		switch attempt {
		case 1:
			return "tok-A", true
		case 2:
			return "tok-B", true
		}
		return "", false
	}})
	m := papi.NewManager(f.url)
	t.Cleanup(m.Close)

	prompts := 0
	p := &hvPrompter{scriptPrompter: scriptPrompter{t: t}}
	p.prompt = func(string) (string, error) { prompts++; return "", nil }
	pc, _, err := authenticateWith(t.Context(), m, p, testUser, testPass, LoginOptions{NoBrowser: true})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	pc.Close()
	if prompts != 2 {
		t.Errorf("prompts = %d, want 2", prompts)
	}
	if *opened {
		t.Error("browser opened despite NoBrowser")
	}
	if got := f.hvTokens; len(got) != 3 || got[1] != "tok-A" || got[2] != "tok-B" {
		t.Errorf("HV tokens = %q, want [\"\" tok-A tok-B]", got)
	}
	notices := strings.Join(p.notices, "\n")
	if !strings.Contains(notices, "token=tok-A") || !strings.Contains(notices, "token=tok-B") {
		t.Errorf("both challenge URLs must be shown: %s", notices)
	}
}

func TestInteractiveCaptchaGivesUpAfterLimit(t *testing.T) {
	noBrowser(t)
	f := newFront(t, &front{challenge: func(int, string) (string, bool) { return "tok", true }})
	m := papi.NewManager(f.url)
	t.Cleanup(m.Close)
	p := &hvPrompter{scriptPrompter: scriptPrompter{t: t}}
	p.prompt = func(string) (string, error) { return "", nil }
	if _, _, err := authenticateWith(t.Context(), m, p, testUser, testPass, LoginOptions{NoBrowser: true}); err == nil {
		t.Fatal("endless CAPTCHA accepted")
	}
	if f.attempts != 1+maxCaptchaRounds {
		t.Errorf("attempts = %d, want %d", f.attempts, 1+maxCaptchaRounds)
	}
}

func TestTOTPFromCredentialsIsSentWithoutPrompting(t *testing.T) {
	f := newFront(t, &front{twoFA: true})
	m := papi.NewManager(f.url)
	t.Cleanup(m.Close)
	tp, _ := ParseTOTP("654321")
	pc, _, err := authenticateWith(t.Context(), m, silentPrompter(t), testUser, testPass, LoginOptions{Creds: Credentials{TOTP: tp}})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	pc.Close()
	if len(f.codes) != 1 || f.codes[0] != "654321" {
		t.Fatalf("2FA codes = %q, want [654321]", f.codes)
	}
}

func TestTOTPGeneratorWaitsForAFreshWindow(t *testing.T) {
	f := newFront(t, &front{twoFA: true})
	m := papi.NewManager(f.url)
	t.Cleanup(m.Close)

	clock := time.Unix(28, 0) // 2 s left in the 0-30 s window
	var slept time.Duration
	origNow, origSleep := nowFunc, sleepFunc
	nowFunc = func() time.Time { return clock }
	sleepFunc = func(_ context.Context, d time.Duration) error { slept += d; clock = clock.Add(d); return nil }
	t.Cleanup(func() { nowFunc, sleepFunc = origNow, origSleep })

	tp, _ := ParseTOTP("otpauth://totp/x?secret=" + b32("12345678901234567890"))
	pc, _, err := authenticateWith(t.Context(), m, silentPrompter(t), testUser, testPass, LoginOptions{Creds: Credentials{TOTP: tp}})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	pc.Close()
	if slept != 2*time.Second {
		t.Errorf("slept %v, want 2s", slept)
	}
	if want := tp.Code(time.Unix(30, 0)); len(f.codes) != 1 || f.codes[0] != want {
		t.Fatalf("2FA codes = %q, want the next window's %s", f.codes, want)
	}
}

func TestBrowserOutputIsSilenced(t *testing.T) {
	prevOut, prevErr := browser.Stdout, browser.Stderr
	t.Cleanup(func() { browser.Stdout, browser.Stderr = prevOut, prevErr })
	browser.Stdout, browser.Stderr = &bytes.Buffer{}, &bytes.Buffer{}
	silenceBrowser()
	if browser.Stdout != io.Discard || browser.Stderr != io.Discard {
		t.Fatal("browser child output still reaches the terminal")
	}
}
