// Copyright (C) 2019 Michael J. Fromberger. All Rights Reserved.

package otp_test

import (
	"testing"

	"github.com/creachadair/mds/mtest"
	"github.com/creachadair/otp"
)

var googleTests = []struct {
	key     string
	counter uint64
	otp     string
}{
	// Manually generated compatibility test vectors for Google authenticator.
	//
	// To verify these test vectors, or to generate new ones, manually enter the
	// key and set "time-based" to off. The first key shown is for index 1, and
	// refreshing increments the index sequentially.
	{"aaaa aaaa aaaa aaaa", 1, "812658"},
	{"aaaa aaaa aaaa aaaa", 2, "073348"},
	{"aaaa aaaa aaaa aaaa", 3, "887919"},
	{"aaaa aaaa aaaa aaaa", 4, "320986"},
	{"aaaa aaaa aaaa aaaa", 5, "435986"},

	{"abcd efgh ijkl mnop", 1, "317963"},
	{"abcd efgh ijkl mnop", 2, "625848"},
	{"abcd efgh ijkl mnop", 3, "281014"},
	{"abcd efgh ijkl mnop", 4, "709708"},
	{"abcd efgh ijkl mnop", 5, "522086"},

	// These are time-based codes. Enter the key in the authenticator app and
	// select "time-based". Copy a code and use "date +%s" to get the time in
	// seconds.  The default timestep is based on a 30-second window.
	{"aaaa bbbb cccc dddd", 1642868750 / 30, "349451"},
	{"aaaa bbbb cccc dddd", 1642868800 / 30, "349712"},
	{"aaaa bbbb cccc dddd", 1642868822 / 30, "367384"},
	{"aaaa bbbb cccc dddd", 1642869021 / 30, "436225"},
}

func TestDefaultHOTP(t *testing.T) {
	for _, test := range googleTests {
		got, err := otp.DefaultHOTP(test.key, test.counter)
		if err != nil {
			t.Errorf("Invalid key: %v", err)
		} else if got != test.otp {
			t.Errorf("Wrong OTP: got %q, want %q", got, test.otp)
		}
		if t.Failed() {
			t.Logf("DefaultHOTP(%q, %v)", test.key, test.counter)
		}
	}
}

func TestConfig_Next(t *testing.T) {
	const testKey = "aaaa aaaa aaaa aaaa"
	var cfg otp.Config
	if err := cfg.ParseKey(testKey); err != nil {
		t.Fatalf("ParseKey %q failed: %v", testKey, err)
	}
	var nrun int
	for _, test := range googleTests {
		if test.key != testKey {
			continue
		}
		nrun++
		got := cfg.Next()
		if got != test.otp {
			t.Errorf("Next [counter=%d]: got %q, want %q", cfg.Counter, got, test.otp)
		}
		if cfg.Counter != test.counter {
			t.Errorf("Next counter: got %d, want %d", cfg.Counter, test.counter)
		}
	}
	if nrun == 0 {
		t.Fatal("Found no matching test cases")
	}
}

func TestGoogleAuthCompat(t *testing.T) {
	for _, test := range googleTests {
		key, err := otp.ParseKey(test.key)
		if err != nil {
			t.Errorf("ParseKey(%q) failed: %v", test.key, err)
			continue
		}
		t.Run("Standard-"+test.otp, func(t *testing.T) {
			cfg := otp.Config{Key: string(key)}
			got := cfg.HOTP(test.counter)
			if got != test.otp {
				t.Errorf("Key %q HOTP(%d) got %q, want %q", test.key, test.counter, got, test.otp)
			}
		})

		t.Run("Custom-"+test.otp, func(t *testing.T) {
			cfg := otp.Config{
				Key: string(key),

				// Map digits to corresponding letters 0=a, 1=b, etc.
				Format: func(hash []byte, nd int) string {
					v := otp.Truncate(hash)
					buf := make([]byte, nd)
					for i := nd - 1; i >= 0; i-- {
						buf[i] = byte(v%10) + byte('a')
						v /= 10
					}
					return string(buf)
				},
			}
			got := cfg.HOTP(test.counter)
			want := digitsToLetters(test.otp)
			if got != want {
				t.Errorf("Key %q HOTP(%d) got %q, want %q", test.key, test.counter, got, want)
			}
		})
	}
}

func TestFormatBounds(t *testing.T) {
	cfg := otp.Config{
		Key:      "whatever",
		TimeStep: func() uint64 { return 1 },

		// Request 5 digits, but generate 8.
		// This should cause code generation to panic.
		Digits: 5,
		Format: func(_ []byte, nd int) string {
			return "12345678" // N.B. not 5
		},
	}
	t.Run("Panic", func(t *testing.T) {
		mtest.MustPanic(t, func() { t.Logf("Got code: %v", cfg.TOTP()) })
	})
}

func TestFormatAlphabet(t *testing.T) {
	tests := []struct {
		alphabet string
		want     string
	}{
		{"XYZPDQ", "PQXPP"},
		{"0123456789", "43645"},
	}
	for _, test := range tests {
		cfg := otp.Config{
			Key:    "whatever",
			Digits: 5,
			Format: otp.FormatAlphabet(test.alphabet),
		}
		got := cfg.HOTP(1)
		if got != test.want {
			t.Errorf("[%q].HOTP(1) failed: got %q, want %q", test.alphabet, got, test.want)
		}
	}
}

// digitsToLetters maps each decimal digit in s to the corresponding letter in
// the range a..j. It will panic for any value outside this range.
func digitsToLetters(s string) string {
	buf := make([]byte, len(s))
	for i := range s {
		if s[i] < '0' || s[i] > '9' {
			panic("invalid digit")
		}
		buf[i] = s[i] - '0' + 'a'
	}
	return string(buf)
}

/*
[RFC 4226] Appendix D - HOTP Algorithm: Test Values

The following test data uses the ASCII string "12345678901234567890" for the
secret:

  Secret = 0x3132333435363738393031323334353637383930

Table 1 details for each count, the intermediate HMAC value.

  Count    Hexadecimal HMAC-SHA-1(secret, count)
  0        cc93cf18508d94934c64b65d8ba7667fb7cde4b0
  1        75a48a19d4cbe100644e8ac1397eea747a2d33ab
  2        0bacb7fa082fef30782211938bc1c5e70416ff44
  3        66c28227d03a2d5529262ff016a1e6ef76557ece
  4        a904c900a64b35909874b33e61c5938a8e15ed1c
  5        a37e783d7b7233c083d4f62926c7a25f238d0316
  6        bc9cd28561042c83f219324d3c607256c03272ae
  7        a4fb960c0bc06e1eabb804e5b397cdc4b45596fa
  8        1b3c89f65e6c9e883012052823443f048b4332db
  9        1637409809a679dc698207310c8c7fc07290d9e5

Table 2 details for each count the truncated values (both in hexadecimal and
decimal) and then the HOTP value.

  Truncated
  Count    Hexadecimal    Decimal        HOTP
  0        4c93cf18       1284755224     755224
  1        41397eea       1094287082     287082
  2         82fef30        137359152     359152
  3        66ef7655       1726969429     969429
  4        61c5938a       1640338314     338314
  5        33c083d4        868254676     254676
  6        7256c032       1918287922     287922
  7         4e5b397         82162583     162583
  8        2823443f        673399871     399871
  9        2679dc69        645520489     520489

[RFC 6238] Appendix B.  Test Vectors

This section provides test values that can be used for the HOTP time-based
variant algorithm interoperability test.

The test token shared secret uses the ASCII string value
"12345678901234567890".  With Time Step X = 30, and the Unix epoch as the
initial value to count time steps, where T0 = 0, the TOTP algorithm will
display the following values for specified modes and timestamps.

+-------------+--------------+------------------+----------+--------+
|  Time (sec) |   UTC Time   | Value of T (hex) |   TOTP   |  Mode  |
+-------------+--------------+------------------+----------+--------+
|      59     |  1970-01-01  | 0000000000000001 | 94287082 |  SHA1  |
|             |   00:00:59   |                  |          |        |
|  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
|             |   01:58:29   |                  |          |        |
|  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
|             |   01:58:31   |                  |          |        |
|  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
|             |   23:31:30   |                  |          |        |
|  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
|             |   03:33:20   |                  |          |        |
| 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
|             |   11:33:20   |                  |          |        |
+-------------+--------------+------------------+----------+--------+
*/
