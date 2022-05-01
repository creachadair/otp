// Copyright (C) 2020 Michael J. Fromberger. All Rights Reserved.

package otpauth_test

import (
	"strings"
	"testing"

	"github.com/creachadair/otp/otpauth"
)

func TestFromSpec(t *testing.T) {
	// Test vector adapted from
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	const base = `totp/ACME%20Co:john.doe@email.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30`
	const part = "//" + base
	const full = "otpauth://" + base

	const (
		wantType      = "totp"
		wantIssuer    = "ACME Co"
		wantAccount   = "john.doe@email.com"
		wantRawSecret = "JBSWY3DPEHPK3PXP"
		wantSecret    = "Hello!\xde\xad\xbe\xef"
		wantAlgorithm = "SHA1"
		wantDigits    = 6
		wantPeriod    = 30
	)

	// Check parsing with and without the scheme prefix.
	for _, input := range []string{base, part, full} {
		t.Run("ParseURL", func(t *testing.T) {
			u, err := otpauth.ParseURL(input)
			if err != nil {
				t.Fatalf("ParseURL(%q) failed: %v", input, err)
			}
			if u.Type != wantType {
				t.Errorf("Type: got %q, want %q", u.Type, wantType)
			}
			if u.Issuer != wantIssuer {
				t.Errorf("Issuer: got %q, want %q", u.Issuer, wantIssuer)
			}
			if u.Account != wantAccount {
				t.Errorf("Account: got %q, want %q", u.Account, wantAccount)
			}
			if u.RawSecret != wantRawSecret {
				t.Errorf("RawSecret: got %q, want %q", u.RawSecret, wantRawSecret)
			}
			if got, err := u.Secret(); err != nil {
				t.Errorf("Secret %q failed: %v", u.RawSecret, err)
			} else if string(got) != wantSecret {
				t.Errorf("Secret: got %q, want %q", string(got), wantSecret)
			}
			if u.Algorithm != wantAlgorithm {
				t.Errorf("Algorithm: got %q, want %q", u.Algorithm, wantAlgorithm)
			}
			if u.Digits != wantDigits {
				t.Errorf("Digits: got %q, want %q", u.Digits, wantDigits)
			}
			if u.Period != wantPeriod {
				t.Errorf("Period: got %q, want %q", u.Period, wantPeriod)
			}
		})
	}
}

func TestEncoding(t *testing.T) {
	tests := []struct {
		*otpauth.URL
		want string
	}{
		{&otpauth.URL{
			Type:    "totp",
			Account: "foo",
		}, "otpauth://totp/foo"},

		{&otpauth.URL{
			Type:      "totp",
			Account:   "quux",
			Algorithm: "sha256",
			RawSecret: "MZUXG2DZEBTGS43I",
		}, "otpauth://totp/quux?algorithm=SHA256&secret=MZUXG2DZEBTGS43I"},

		{&otpauth.URL{
			Type:    "hotp",
			Account: "your@uncle.co.uk",
			Issuer:  "bob",
		}, "otpauth://hotp/bob:your@uncle.co.uk?counter=0&issuer=bob"},

		{&otpauth.URL{
			Type:    "random",
			Issuer:  "two kittens",
			Account: "in@trench-coat.org",
			Digits:  8,
			Period:  60,
		}, "otpauth://random/two%20kittens:in@trench-coat.org?digits=8&issuer=two%20kittens&period=60"},
	}
	for _, test := range tests {
		t.Run("String", func(t *testing.T) {
			got := test.URL.String()
			if got != test.want {
				t.Errorf("Input: %+v\nWrong encoding:\n got: %q\nwant: %q", test.URL, got, test.want)
			}
		})
		t.Run("Text", func(t *testing.T) {
			// The URL should encode to the same format as String.
			text, err := test.URL.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText failed: %v", err)
			}
			if got := string(text); got != test.want {
				t.Errorf("MarshalText: got %#q, want %#q", got, test.want)
			}

			// Unmarshaling the string should result in an equivalent URL.
			// N.B. not necessarily equal, because of auto-population of defaults.
			var cmp otpauth.URL
			if err := cmp.UnmarshalText(text); err != nil {
				t.Fatalf("UnmarshalText failed: %v", err)
			}
			if got, want := cmp.String(), test.URL.String(); got != want {
				t.Errorf("UNmarshalText: got %#q, want %#q", got, want)
			}
		})
	}
}

func TestParseeErrors(t *testing.T) {
	tests := []struct {
		input string
		etext string
	}{
		{"http://www.bogus.com", "invalid scheme"},

		{"otpauth://totp", "invalid type/label"},
		{"otpauth://totp/", "invalid type/label"},
		{"otpauth:///", "invalid type/label"},
		{"otpauth:///label", "invalid type/label"},

		{"otpauth://hotp/%xx", "invalid URL escape"},
		{"otpauth://totp/foo?invalid=what", "invalid parameter"},
		{"otpauth://totp/foo?digits=25&invalid=what", "invalid parameter"},

		{"otpauth://totp/x:", "empty account name"},
		{"otpauth://totp/:y", "empty issuer"},

		{"otpauth://ok/a:b?digits=x", "invalid integer value"},
		{"otpauth://ok/a:b?period=x", "invalid integer value"},
		{"otpauth://ok/a:b?counter=x", "invalid integer value"},
		{"otpauth://ok/a:b?algorithm=x%2x", "invalid value"},
	}
	for _, test := range tests {
		u, err := otpauth.ParseURL(test.input)
		if err == nil {
			t.Errorf("ParseURL(%q): got %+v, wanted error", test.input, u)
			continue
		}
		if got := err.Error(); !strings.Contains(got, test.etext) {
			t.Errorf("ParseURL(%q): got error %v, wanted %q", test.input, err, test.etext)
		}
	}
}
