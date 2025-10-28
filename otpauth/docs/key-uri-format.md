> [!NOTE]
> This is a mirror of the OTP key URI documentation from
> the now-archived Google Authenticator wiki.
> The original is
> https://github.com/google/google-authenticator/wiki/Key-Uri-Format

Introduction
============

Secret keys may be encoded in QR codes as a URI with the following format:

```
otpauth://TYPE/LABEL?PARAMETERS
```

Examples
--------

Provision a TOTP key for user `alice@google.com`, to use with a service provided by Example, Inc:

```
otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
```

This Base32 encoded key "JBSWY3DPEHPK3PXP" has the value:

```
byte[] key = { 'H', 'e', 'l', 'l', 'o', '!', (byte) 0xDE, (byte) 0xAD, (byte) 0xBE, (byte) 0xEF };
```

Here's another example with all optional parameters supplied

```
otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30
```

Live Demo
---------

Try [Browser Authenticator Demo](https://authenticator.ppl.family/), source at <https://git.coolaj86.com/coolaj86/browser-authenticator.js>

Types
=====

Valid types are **`hotp`** and **`totp`**, to distinguish whether the key will be used
for counter-based HOTP or for TOTP.

Label
=====

The label is used to identify which account a key is associated with. It contains an account
name, which is a URI-encoded string, optionally prefixed by an issuer string identifying
the provider or service managing that account. This issuer prefix can be used to prevent
collisions between different accounts with different providers that might be identified
using the same account name, e.g. the user's email address.

The issuer prefix and account name should be separated by a literal or url-encoded colon,
and optional spaces may precede the account name. Neither issuer nor account name may
themselves contain a colon. Represented in ABNF according to [RFC 5234](http://tools.ietf.org/html/rfc5234):

```
label = accountname / issuer (“:” / “%3A”) *”%20” accountname
```

Valid values might include `Example:alice@gmail.com`, `Provider1:Alice%20Smith` or
`Big%20Corporation%3A%20alice%40bigco.com`.

We recommend using **both** an issuer label prefix and an issuer parameter, described below.

Parameters
==========

Secret
------

**REQUIRED**: The **`secret`** parameter is an arbitrary key value encoded in Base32
according to [RFC 3548](http://tools.ietf.org/html/rfc3548). The padding specified
in [RFC 3548 section 2.2](https://tools.ietf.org/html/rfc3548#section-2.2) is not
required and should be omitted.

Issuer
------

**STRONGLY RECOMMENDED**: The **`issuer`** parameter is a string value indicating
the provider or service this account is associated with, URL-encoded according to
[RFC 3986](http://tools.ietf.org/html/rfc3986). If the issuer parameter is absent,
issuer information may be taken from the issuer prefix of the label. If both issuer
parameter and issuer label prefix are present, they should be equal.

Valid values corresponding to the label prefix examples above would be: `issuer=Example`,
`issuer=Provider1`, and `issuer=Big%20Corporation`.

Older Google Authenticator implementations ignore the issuer parameter and rely upon
the issuer label prefix to disambiguate accounts. Newer implementations will use the
issuer parameter for internal disambiguation, it will not be displayed to the user.
We recommend using both issuer label prefix and issuer parameter together to safely
support both old and new Google Authenticator versions.

Algorithm
---------

**OPTIONAL**: The **`algorithm`**  may have the values:

* SHA1 (Default)
* SHA256
* SHA512

> Currently, the algorithm parameter is ignored by the Google Authenticator implementations.

Digits
------

**OPTIONAL**: The **`digits`** parameter may have the values 6 or 8, and determines how
long of a one-time passcode to display to the user. The default is 6.

> Currently, on Android and Blackberry the digits parameter is ignored by the Google Authenticator implementation.

Counter
-------

**REQUIRED** if `type` is **`hotp`**: The **`counter`** parameter is required when provisioning
a key for use with HOTP. It will set the initial counter value.

Period
------

**OPTIONAL** only if `type` is **`totp`**: The `period` parameter defines a period that a
TOTP code will be valid for, in seconds. The default value is 30.

> Currently, the period parameter is ignored by the Google Authenticator implementations.
