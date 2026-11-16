package identity

import (
	"testing"
	"time"
)

func TestCredentialLifetimes(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		value   string
		expires time.Time
	}{
		{"1h", now.Add(time.Hour)},
		{"24h", now.Add(24 * time.Hour)},
		{"72h", now.Add(72 * time.Hour)},
		{"1w", now.Add(7 * 24 * time.Hour)},
		{"2w", now.Add(14 * 24 * time.Hour)},
		{"1mo", now.AddDate(0, 1, 0)},
		{"3mo", now.AddDate(0, 3, 0)},
		{"6mo", now.AddDate(0, 6, 0)},
	} {
		t.Run(tc.value, func(t *testing.T) {
			ttl, err := credentialLifetime(tc.value, now)
			if err != nil || !now.Add(ttl).Equal(tc.expires) {
				t.Fatalf("expiry = %v, err = %v; want %v", now.Add(ttl), err, tc.expires)
			}
		})
	}
	for _, value := range []string{"forever", "-1h", "0h", "1y", ""} {
		if _, err := credentialLifetime(value, now); err == nil {
			t.Fatalf("accepted unsupported lifetime %q", value)
		}
	}
}
