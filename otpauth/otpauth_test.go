// Copyright (C) 2020 Michael J. Fromberger. All Rights Reserved.

package otpauth_test

import (
	"testing"

	"github.com/creachadair/otp/otpauth"
)

func TestFromSpec(t *testing.T) {
	// Test vector adapted from
	// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
	const input = `otpauth://totp/ACME%20Co:john.doe@email.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30`

	u, err := otpauth.ParseURL(input)
	if err != nil {
		t.Fatalf("ParseURL(%q) failed: %v", input, err)
	}

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
	if got, err := u.ParseSecret(); err != nil {
		t.Errorf("ParseSecret %q failed: %v", u.RawSecret, err)
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
}

func TestString(t *testing.T) {
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
		got := test.URL.String()
		if got != test.want {
			t.Errorf("Input: %+v\nWrong encoding:\n got: %q\nwant: %q", test.URL, got, test.want)
		}
	}
}
