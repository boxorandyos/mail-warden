package identity

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

func TOTPAuthURL(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("period", "30")
	v.Set("digits", "6")
	return "otpauth://totp/" + label + "?" + v.Encode()
}

func ValidateTOTP(secret, code string, now time.Time) bool {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	code = strings.TrimSpace(code)
	if secret == "" || len(code) != 6 {
		return false
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		raw, err = base32.StdEncoding.DecodeString(secret)
		if err != nil {
			return false
		}
	}
	counter := now.UTC().Unix() / 30
	for delta := int64(-1); delta <= 1; delta++ {
		if totpAt(raw, counter+delta) == code {
			return true
		}
	}
	return false
}

func totpAt(secret []byte, counter int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", bin%1000000)
}
