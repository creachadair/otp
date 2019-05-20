// Copyright (C) 2019 Michael J. Fromberger. All Rights Reserved.

package otp

import (
	"encoding/hex"
	"testing"
)

type testCase struct {
	counter   uint64
	trunc     uint64
	otp       string
	hexDigest string
}

var tests = []testCase{
	// Test vectors from Appendix D of RFC 4226.
	{0, 1284755224, "755224", "cc93cf18508d94934c64b65d8ba7667fb7cde4b0"},
	{1, 1094287082, "287082", "75a48a19d4cbe100644e8ac1397eea747a2d33ab"},
	{2, 137359152, "359152", "0bacb7fa082fef30782211938bc1c5e70416ff44"},
	{3, 1726969429, "969429", "66c28227d03a2d5529262ff016a1e6ef76557ece"},
	{4, 1640338314, "338314", "a904c900a64b35909874b33e61c5938a8e15ed1c"},
	{5, 868254676, "254676", "a37e783d7b7233c083d4f62926c7a25f238d0316"},
	{6, 1918287922, "287922", "bc9cd28561042c83f219324d3c607256c03272ae"},
	{7, 82162583, "162583", "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa"},
	{8, 673399871, "399871", "1b3c89f65e6c9e883012052823443f048b4332db"},
	{9, 645520489, "520489", "1637409809a679dc698207310c8c7fc07290d9e5"},

	// Test vectors from Appendix B of RFC 6238.
	//
	// Note that these cases have been adjusted to fit the implementation, which
	// does not divide before conversion. The results are equivalent, but the
	// trunc values have been expanded to their original precision.
	{59 / 30, 1094287082, "287082", ""},
	{1111111109 / 30, 907081804, "081804", ""},
	{1111111111 / 30, 414050471, "050471", ""},
	{1234567890 / 30, 689005924, "005924", ""},
	{20000000000 / 30, 1465353130, "353130", ""},
}

func (tc testCase) Run(t *testing.T, c Config, gen func(uint64) string) {
	t.Helper()

	hmac := c.hmac(tc.counter)
	trunc := truncate(hmac)
	hexDigest := hex.EncodeToString(hmac)
	otp := gen(tc.counter)

	if tc.hexDigest != "" && hexDigest != tc.hexDigest {
		t.Errorf("Counter %d digest: got %q, want %q", tc.counter, hexDigest, tc.hexDigest)
	}
	if trunc != tc.trunc {
		t.Errorf("Counter %d trunc: got %d, want %0d", tc.counter, trunc, tc.trunc)
	}
	if otp != tc.otp {
		t.Errorf("Counter %d HOTP: got %q, want %q", tc.counter, otp, tc.otp)
	}
}

func TestHOTP(t *testing.T) {
	cfg := Config{
		Key: "12345678901234567890",
	}
	for _, test := range tests {
		test.Run(t, cfg, cfg.HOTP)
	}
}

func TestTOTP(t *testing.T) {
	var timeNow uint64 // simulated clock, uses the test case index

	cfg := Config{
		Key:      "12345678901234567890",
		TimeStep: func() uint64 { return timeNow },
	}
	for _, test := range tests {
		timeNow = test.counter
		test.Run(t, cfg, func(uint64) string { return cfg.TOTP() })
	}
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
