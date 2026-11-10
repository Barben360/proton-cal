package auth

// TOTP for non-interactive logins (fork addition): either a ready code, or an
// otpauth:// URI from which the code is computed when it is needed (RFC 6238),
// so a code resolved long before the 2FA step cannot go stale.

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 default; HMAC-SHA1 is not broken for TOTP
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// totpMargin is how close to the end of its window a computed code may be
// used; closer than this, Wait asks to wait for the next window.
const totpMargin = 5 * time.Second

// TOTP yields the 2FA code for a login.
type TOTP struct {
	static string // a ready code (no secret)

	secret []byte
	algo   func() hash.Hash
	digits int
	period int64
}

// ParseTOTP accepts a 6-8 digit code or an otpauth://totp/ URI (secret,
// optional algorithm SHA1/SHA256/SHA512, digits 6-8, period). Errors never
// include the input, which may hold the secret.
func ParseTOTP(s string) (*TOTP, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(strings.ToLower(s), "otpauth://") {
		if len(s) < 6 || len(s) > 8 || strings.Trim(s, "0123456789") != "" {
			return nil, errors.New("TOTP: expected a 6-8 digit code or an otpauth://totp/ URI")
		}
		return &TOTP{static: s}, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("TOTP: malformed otpauth URI")
	}
	if !strings.EqualFold(u.Host, "totp") {
		return nil, errors.New("TOTP: only otpauth://totp/ URIs are supported")
	}
	q := u.Query()
	raw := strings.ToUpper(strings.TrimRight(strings.ReplaceAll(q.Get("secret"), " ", ""), "="))
	if raw == "" {
		return nil, errors.New("TOTP: otpauth URI has no secret")
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(raw)
	if err != nil || len(secret) == 0 {
		return nil, errors.New("TOTP: otpauth secret is not valid base32")
	}
	t := &TOTP{secret: secret, algo: sha1.New, digits: 6, period: 30}
	switch strings.ToUpper(q.Get("algorithm")) {
	case "", "SHA1":
	case "SHA256":
		t.algo = sha256.New
	case "SHA512":
		t.algo = sha512.New
	default:
		return nil, errors.New("TOTP: unsupported algorithm (SHA1, SHA256 or SHA512)")
	}
	if d := q.Get("digits"); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || n < 6 || n > 8 {
			return nil, errors.New("TOTP: digits must be 6, 7 or 8")
		}
		t.digits = n
	}
	if p := q.Get("period"); p != "" {
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil || n <= 0 {
			return nil, errors.New("TOTP: period must be a positive number of seconds")
		}
		t.period = n
	}
	return t, nil
}

// Code returns the code valid at now.
func (t *TOTP) Code(now time.Time) string {
	if t.secret == nil {
		return t.static
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(now.Unix()/t.period)) //nolint:gosec // non-negative after 1970
	mac := hmac.New(t.algo, t.secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for range t.digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", t.digits, bin%mod)
}

// Wait returns how long to wait before Code yields a code with at least
// totpMargin of validity left (0 for a static code).
func (t *TOTP) Wait(now time.Time) time.Duration {
	if t.secret == nil {
		return 0
	}
	periodNs := t.period * int64(time.Second)
	left := time.Duration(periodNs - now.UnixNano()%periodNs)
	if left < totpMargin {
		return left
	}
	return 0
}
