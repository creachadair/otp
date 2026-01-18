// Copyright (C) 2020 Michael J. Fromberger. All Rights Reserved.

package otpauth_test

import (
	"strings"
	"testing"

	"github.com/creachadair/otp/otpauth"
	"github.com/google/go-cmp/cmp"
)

func TestValid(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		secret string
		want   *otpauth.URL
	}{
		// Test vector adapted from
		// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
		{"SpecExample",
			`otpauth://totp/ACME%20Co:john.doe@email.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30`,
			"Hello!\xde\xad\xbe\xef",
			&otpauth.URL{
				Type: "totp", Issuer: "ACME Co", Account: "john.doe@email.com", RawSecret: "JBSWY3DPEHPK3PXP",
				Algorithm: "SHA1", Digits: 6, Period: 30, Counter: 0,
			}},

		{"AllDefaults",
			`otpauth://totp/minsc@boo.com?secret=M5XSAZTPOIQHI2DFEBSXSZLT`,
			"go for the eyes",
			&otpauth.URL{
				Type: "totp", Account: "minsc@boo.com", RawSecret: "M5XSAZTPOIQHI2DFEBSXSZLT",
				Algorithm: "SHA1", Digits: 6, Period: 30,
			}},

		// Verify that places where extra whitespace is allowed, e.g., around the
		// name of the issuer or after the ":" separating it from the account,
		// are properly handled.
		{"ExtraSpace",
			`otpauth://hotp/fippy%20darkpaw%20%3a%20%20gnoll%20runner?digits=8&period=100&counter=5`,
			"",
			&otpauth.URL{
				Type: "hotp", Issuer: "fippy darkpaw", Account: "gnoll runner",
				Algorithm: "SHA1", Digits: 8, Period: 100, Counter: 5,
			}},
	}

	for _, tc := range tests {
		// Check parsing with and without the scheme prefix.
		full := tc.input
		part := strings.TrimPrefix(full, "otpauth:")
		base := strings.TrimPrefix(part, "//")

		t.Run(tc.name, func(t *testing.T) {
			for _, url := range []string{base, part, full} {
				u, err := otpauth.ParseURL(url)
				if err != nil {
					t.Errorf("ParseURL(%q): unexpected error: %v", url, err)
					continue
				}
				if diff := cmp.Diff(u, tc.want); diff != "" {
					t.Errorf("Wrong URL (-got, +want):\n%s", diff)
					continue
				}
				got, err := u.Secret()
				if err != nil {
					t.Errorf("Parsing secret %q: unexpected error: %v", u.RawSecret, err)
				} else if string(got) != tc.secret {
					t.Errorf("Parsed secret: got %q, want %q", string(got), tc.secret)
				}
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
				t.Errorf("UnmarshalText: got %#q, want %#q", got, want)
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

// Test input synthesized using Google Authenticator.  To re-generate this
// test example:
//
//   - Create a new entry named "test 1" with the key "fuzzlebuzzlegibbledibble", counter-based.
//     Generate 3 codes from this (advancing the counter from 0 to 3).
//   - Create a new entry named "test 2" with the key "applepieispeachy", time-based.
//   - Export these two entries together as a single QR code.
//   - Parse the QR code to export the migration URL.
const testMigrationURL = `otpauth-migration://offline?data=CiEKDy0zlZA0zlZDICFZBoCFZBIGdGVzdCAxIAEoATABOAMKGgoKA96yPQREnkAI%2BBIGdGVzdCAyIAEoATACEAIYASAA`

func TestParseMigrationURL(t *testing.T) {
	u, err := otpauth.ParseMigrationURL(testMigrationURL)
	if err != nil {
		t.Fatalf("ParseMigrationURL: unexpected error: %v", err)
	}
	want := []*otpauth.URL{{
		Type:      "hotp",
		Account:   "test 1",
		RawSecret: "FUZZLEBUZZLEGIBBLEDIBBLE",
		Algorithm: "SHA1",
		Digits:    6,
		Counter:   3,
		Period:    30, // default
	}, {
		Type:      "totp",
		Account:   "test 2",
		RawSecret: "APPLEPIEISPEACHY",
		Algorithm: "SHA1",
		Digits:    6,
		Period:    30, // default
	}}
	if diff := cmp.Diff(u, want); diff != "" {
		t.Errorf("Parsed (-got, +want):\n%s", diff)
	}

	// Verify that if we render it to a new migration URL and re-parse, we get the same stuff.
	// The URL itself might not be equal because of field ordering, defaults, etc.
	s, err := otpauth.MigrationURL(u)
	if err != nil {
		t.Fatalf("Render migration URL: %v", err)
	}
	t.Logf("\nOld: %q\nNew: %q", testMigrationURL, s)

	v, err := otpauth.ParseMigrationURL(s)
	if err != nil {
		t.Fatalf("ParseMigrationURL: unexpected error: %v", err)
	}
	if diff := cmp.Diff(v, want); diff != "" {
		t.Errorf("Parsed (-got, +want):\n%s", diff)
	}
}

func TestMigrationURL(t *testing.T) {
	input := []*otpauth.URL{{
		Type:      "totp",
		Algorithm: "SHA1",
		Account:   "test 1",
		Issuer:    "minsc",
		RawSecret: "MEEPMEEP",
		Digits:    6,
		Period:    30, // default
	}, {
		Type:      "hotp",
		Algorithm: "SHA256",
		Account:   "test 2",
		Issuer:    "boo",
		RawSecret: "OYVEY",
		Digits:    8,
		Period:    30, // default
	}, {
		Type:      "totp",
		Algorithm: "MD5",
		Account:   "test 3",
		RawSecret: "APPLEPIEISPEACHY",
		Digits:    6,
		Period:    30, // default
	}}

	// Verify that we can convert the input to a URL and back
	s, err := otpauth.MigrationURL(input)
	if err != nil {
		t.Fatalf("MigrationURL failed; %v", err)
	}
	t.Logf("Migration URL: %q", s)

	us, err := otpauth.ParseMigrationURL(s)
	if err != nil {
		t.Fatalf("Parse migration failed; %v", err)
	}
	if diff := cmp.Diff(us, input); diff != "" {
		t.Fatalf("Parsed (-got, +want):\n%s", diff)
	}
}

func TestMigrationURLErrors(t *testing.T) {
	tests := []struct {
		input *otpauth.URL
		want  string
	}{
		// If the type is set, it must be "hotp" or "totp" (ignoring case).
		{&otpauth.URL{Type: "bogus"}, "unknown type"},

		// If the algorithm is set, it must be one known by the Google enumeration.
		{&otpauth.URL{Type: "totp", Algorithm: "wat"}, "unsupported algorithm"},

		// Only 6 or 8 digits are supported by the Authenticator proto.
		{&otpauth.URL{Type: "totp", Digits: 12}, "unsupported digit count"},

		// If we have a secret, it had better be valid.
		{&otpauth.URL{Type: "hotp", RawSecret: "*****"}, "illegal base32 data"},
	}
	for _, tc := range tests {
		s, err := otpauth.MigrationURL([]*otpauth.URL{tc.input})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Input: %+v\ngot %q, %v, want %q", tc.input, s, err, tc.want)
		} else {
			t.Logf("Got expected error: %v", err)
		}
	}
}
