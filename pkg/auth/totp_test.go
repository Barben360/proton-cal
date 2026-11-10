package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

func b32(s string) string {
	return strings.TrimRight(base32.StdEncoding.EncodeToString([]byte(s)), "=")
}

// RFC 6238 appendix B test vectors (8 digits).
func TestTOTPRFC6238Vectors(t *testing.T) {
	secrets := map[string]string{
		"SHA1":   "12345678901234567890",
		"SHA256": "12345678901234567890123456789012",
		"SHA512": "1234567890123456789012345678901234567890123456789012345678901234",
	}
	vectors := []struct {
		unix int64
		algo string
		want string
	}{
		{59, "SHA1", "94287082"}, {59, "SHA256", "46119246"}, {59, "SHA512", "90693936"},
		{1111111109, "SHA1", "07081804"}, {1111111109, "SHA256", "68084774"}, {1111111109, "SHA512", "25091201"},
		{20000000000, "SHA1", "65353130"}, {20000000000, "SHA256", "77737706"}, {20000000000, "SHA512", "47863826"},
	}
	for _, v := range vectors {
		uri := "otpauth://totp/Proton:me?secret=" + b32(secrets[v.algo]) + "&algorithm=" + v.algo + "&digits=8&period=30"
		tp, err := ParseTOTP(uri)
		if err != nil {
			t.Fatalf("%s: %v", v.algo, err)
		}
		if got := tp.Code(time.Unix(v.unix, 0)); got != v.want {
			t.Errorf("%s @%d = %s, want %s", v.algo, v.unix, got, v.want)
		}
	}
}

func TestTOTPURIDefaults(t *testing.T) {
	// No algorithm/digits/period: SHA1, 6 digits, 30 s. Lowercase secret with
	// padding is accepted. 94287082 truncated to 6 digits = 287082.
	tp, err := ParseTOTP("otpauth://totp/x?secret=" + strings.ToLower(base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))))
	if err != nil {
		t.Fatal(err)
	}
	if got := tp.Code(time.Unix(59, 0)); got != "287082" {
		t.Fatalf("code = %s, want 287082", got)
	}
}

func TestTOTPStaticCode(t *testing.T) {
	tp, err := ParseTOTP(" 123456\n")
	if err != nil {
		t.Fatal(err)
	}
	if got := tp.Code(time.Unix(0, 0)); got != "123456" {
		t.Fatalf("static code = %q", got)
	}
	if d := tp.Wait(time.Unix(29, 0)); d != 0 {
		t.Fatalf("a static code must not wait, got %v", d)
	}
}

func TestTOTPRejectsBadInput(t *testing.T) {
	for _, in := range []string{
		"",
		"12ab56",
		"otpauth://totp/x",             // no secret
		"otpauth://totp/x?secret=!!!!", // not base32
		"otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5", // unsupported
		"otpauth://totp/x?secret=GEZDGNBV&digits=4",
		"otpauth://totp/x?secret=GEZDGNBV&period=0",
		"otpauth://hotp/x?secret=GEZDGNBV", // counter-based, not TOTP
	} {
		if _, err := ParseTOTP(in); err == nil {
			t.Errorf("ParseTOTP(%q) accepted", in)
		}
	}
}

func TestTOTPWaitsOutAnExpiringWindow(t *testing.T) {
	tp, err := ParseTOTP("otpauth://totp/x?secret=" + b32("12345678901234567890"))
	if err != nil {
		t.Fatal(err)
	}
	if d := tp.Wait(time.Unix(28, 0)); d != 2*time.Second {
		t.Errorf("2 s before the window ends: wait %v, want 2s", d)
	}
	if d := tp.Wait(time.Unix(10, 0)); d != 0 {
		t.Errorf("mid-window: wait %v, want 0", d)
	}
}

func TestTOTPErrorNeverEchoesTheSecret(t *testing.T) {
	_, err := ParseTOTP("otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&algorithm=MD5")
	if err == nil || strings.Contains(err.Error(), "GEZDGNBVGY3TQOJQ") {
		t.Fatalf("error leaks the secret or is missing: %v", err)
	}
}
