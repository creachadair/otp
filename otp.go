// Copyright (C) 2019 Michael J. Fromberger. All Rights Reserved.

// Package otp generates single use authenticator codes using the TOTP or HOTP
// algorithms specified in RFC 6238 and RFC 4226 respectively.
//
// See https://tools.ietf.org/html/rfc6238, https://tools.ietf.org/html/rfc4226
package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"hash"
	"strconv"
	"strings"
	"time"
)

// TimeWindow returns a time step generator that yields the number of n-second
// intervals elapsed at the current wallclock time since the Unix epoch.
func TimeWindow(n int) func() uint64 {
	return func() uint64 { return uint64(time.Now().Unix()) / uint64(n) }
}

// Config holds the settings the control generation of authenticator codes.
// The only required field is Key, all other fields have sensible defaults.
type Config struct {
	Key string // shared secret between server and user (required)

	Hash     func() hash.Hash // hash constructor (default is sha1.New)
	TimeStep func() uint64    // TOTP time step (default is TimeWindow(30))
	Digits   int              // number of OTP digits (default 6)
}

// ParseKey parses a key encoded as base32, which is the typical format used by
// two-factor authentication setup tools. On success, the parsed key is stored
// into c.Key. Whitespace is ignored.
func (c *Config) ParseKey(s string) error {
	clean := strings.ToUpper(strings.Join(strings.Fields(s), ""))
	if n := len(clean) % 8; n != 0 {
		clean += strings.Repeat("=", 8-n)
	}
	dec, err := base32.StdEncoding.DecodeString(clean)
	if err != nil {
		return err
	}
	c.Key = string(dec)
	return nil
}

// HOTP returns the HOTP code for the specified counter value.
func (c Config) HOTP(counter uint64) string {
	return format(truncate(c.hmac(counter)), c.digits())
}

// TOTP returns the TOTP code for the current time step.
func (c Config) TOTP() string {
	return c.HOTP(c.timeStepWindow())
}

func (c Config) newHash() func() hash.Hash {
	if c.Hash != nil {
		return c.Hash
	}
	return sha1.New
}

func (c Config) digits() int {
	if c.Digits <= 0 {
		return 6
	}
	return c.Digits
}

func (c Config) timeStepWindow() uint64 {
	if c.TimeStep != nil {
		return c.TimeStep()
	}
	return TimeWindow(30)()
}

func (c Config) hmac(counter uint64) []byte {
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], uint64(counter))
	h := hmac.New(c.newHash(), []byte(c.Key))
	h.Write(ctr[:])
	return h.Sum(nil)
}

func truncate(digest []byte) uint64 {
	offset := digest[len(digest)-1] & 0x0f
	code := (uint64(digest[offset]&0x7f) << 24) |
		(uint64(digest[offset+1]) << 16) |
		(uint64(digest[offset+2]) << 8) |
		(uint64(digest[offset+3]) << 0)
	return code
}

const padding = "0000000000000000"

func format(code uint64, width int) string {
	s := strconv.FormatUint(code, 10)
	if len(s) < width {
		s = padding[:width-len(s)] + s // left-pad with zeros
	}
	return s[len(s)-width:]
}
