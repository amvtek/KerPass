# KerPass One-Time Password Algorithm

## 1. Abstract

This document specifies **KerPass EPHEMSEC**, an algorithm for generating
time-synchronized one-time passwords (OTPs) or one-time keys (OTKs). The design extends
the TOTP algorithm (as defined in [RFC 4226][1] and [RFC 6238][2]) by replacing the
static shared secret used in traditional OTP systems with a one-time secret. This secret
is derived by combining an ephemeral secret, established via Diffie-Hellman key
exchange, with a static, account-specific shared secret of the kind typically used in
standard OTP algorithms.

The algorithm also supports incorporating context data into the secret generation process.

Additionally, each OTP/OTK embeds a one-digit time synchronization hint, which
disambiguates the time value used during generation.

These enhancements to the established HOTP/TOTP algorithm provide the following benefits:

1. **Enhanced Server Security**: Because OTP/OTK generation depends on public/private
   key pairs, an attacker who compromises user server-side credentials cannot
   impersonate the user. This contrasts with traditional OTP systems, where access to
   the server-stored shared secret allows full user impersonation.

2. **Stronger Usage Security**: The algorithm supports binding OTP/OTK generation to
   context-specific input. When this context is carefully chosen—for example, the login
   page URL (to mitigate phishing) or connection certificate data (to resist MITM
   attacks) and acquired through a **trusted** agent, the resulting secrets become
   resistant to such attacks.

3. **PAKE Compatibility**: Unlike traditional OTP algorithms, which lack automatic
   resynchronization, this algorithm supports it, making the generated one-time passwords
   compatible with Password-Authenticated Key Exchange ([PAKE][3]) protocols. This
   enables mutual authentication between client and server without relying on a public
   key infrastructure (PKI).

## 2. Context

The primary goal of the KerPass project is to develop an authentication solution in
which a user's smartphone securely hosts credentials compatible with the **KerPass
EPHEMSEC** algorithm, as specified in this document.

The concept of leveraging smartphones as secure authentication devices is well
established. For instance, numerous authenticator apps exist today that implement
one-time password (OTP) generation using the algorithm defined in [RFC 4226][1].

While such applications are simple to use and widely available, they have had limited
impact on the security of web-based applications. Several factors contribute to this
limited success:

1. The design of traditional authenticator apps does not address specific security
   challenges of web applications. In particular, modern web browsers do not provide a
   trusted input interface for entering authentication data, making users vulnerable to
   phishing attacks that capture credentials.
2. Deployment of the corresponding authentication servers introduces additional risks,
   as the stored credentials can be used to impersonate users if compromised.

Traditional OTP systems, such as those specified in [RFC 4226][1], focus primarily on
defining an authenticator app and a corresponding validation server. However, these
systems do not account for the specific challenges of web-based authentication,
particularly the inability of web browsers to provide trusted input paths for entering
authentication codes, leaving users vulnerable to phishing attacks.

KerPass addresses these limitations by introducing two coordinated components: an
authenticator app that incorporates context data into the OTP/OTK computation, and a
browser-integrated Agent responsible for acquiring and supplying this context. This
architecture enables KerPass to resist attacks that traditional OTP deployments are not
designed to mitigate.

A typical authentication flow in the KerPass system proceeds as follows:

1. An Initiator (e.g., a relying web application) sends an authentication request to the
   user's web browser.
2. The KerPass Agent augments the request with context data and renders it as a signed
   2D barcode.
3. A Responder (the authenticator app on the smartphone) scans the barcode and computes
   an OTP/OTK response using the EPHEMSEC algorithm in the Responder role.
4. The user transmits the response back to the Agent, which uses it to initiate an
   authentication protocol with the Initiator.
5. The Initiator runs the EPHEMSEC algorithm in the Initiator role using inputs provided
   by the Agent.

A full specification of the KerPass Agent and the broader authentication system
architecture is outside the scope of this document. However, the simplified description
above is intended to clarify the practical use case and design motivations of the
EPHEMSEC algorithm.

## 3. Functions and Notation

This section defines notation and helper functions used throughout the specification.

- `||`: Denotes byte string concatenation.

- `byte(v)`: Converts an integer or single-character input `v` to a one-byte string.

- `size(bs)`: Returns the length of byte string `bs`, as an integer.

- `BE8(v)`: Returns the 8-byte big-endian encoding of unsigned integer `v`.

- `U64(bs)`: Converts an 8-byte string `bs` into an unsigned 64-bit integer, using
  big-endian interpretation.

- `TLV(tag, bs)`: Constructs a simple Tag-Length-Value encoding.  Returns a byte string
  composed of: 

    ```byte(tag) || byte(size(bs)) || bs```
    - `tag`: An integer identifier (0–255).  
    - `bs`: A byte string of length at most 255.  

## 4. EPHEMSEC Roles

EPHEMSEC distinguishes two roles: Initiator & Responder.

### 4.1 Initiator Role

This role is normally assigned to relying web application.

### 4.2 Responder Role

This role is normally assigned to authenticator application.

## 5. EPHEMSEC Parametrization

An EPHEMSEC protocol instance is defined by a specific selection of cryptographic
primitives and operational parameters. These include:

- A secure hash function,  
- An elliptic-curve Diffie-Hellman (ECDH) function,  
- A key exchange pattern defining key contributions from the parties,  
- Code output parameters specifying how the OTP/OTK values are formatted.

### 5.1 Hash Function

A secure hash function such as SHA-512 is used, with a digest length between 32 and 64
bytes. This hash function is used to instantiate the HKDF key derivation function, as
specified in [RFC 5869][5].

#### 5.1.1 HKDF(salt, ikm, info, L) → byte[L] Function

This function follows the specification in [RFC 5869][5].

- `salt`, `ikm`, and `info` are arbitrary-length byte strings.  
- `L` is a positive integer indicating the desired output length in bytes.  
- The function returns a byte string of length `L`.

### 5.2 ECDH(privKey, PubKey) → byte[DHLEN] Function

This function performs an Elliptic-Curve Diffie-Hellman (ECDH) key agreement over a
specified elliptic curve group, producing a shared secret of fixed length `DHLEN`.

- `privKey`: A private key from an elliptic curve key pair.  
- `PubKey`: A public key from the same elliptic curve group.

The function computes a shared secret using the standard ECDH primitive associated with
the curve in use. The result is a byte string of length `DHLEN`. The specific behavior,
including internal encoding and validation, is determined by the curve and cryptographic
library in use.

An example of a suitable ECDH function is X25519, as defined in [RFC 7748][6],
which yields a 32-byte shared secret.

### 5.3 Key Exchange Pattern

The key exchange pattern determines which types of keys (ephemeral or static) are
contributed by the Initiator and Responder during the ECDH exchanges.

#### 5.3.1 E1S1 Pattern

- Initiator contributes: 1 ephemeral key.  
- Responder contributes: 1 static key.

#### 5.3.2 E1S2 Pattern

- Initiator contributes: 1 ephemeral key and 1 static key.  
- Responder contributes: 1 static key.

#### 5.3.3 E2S2 Pattern

- Initiator contributes: 1 ephemeral key and 1 static key.  
- Responder contributes: 1 ephemeral key and 1 static key.

#### 5.3.4 Rationale for Selecting a Key Exchange Pattern

The choice of key exchange pattern should align with the authentication guarantees
provided by the method used to validate the generated OTP or OTK.

If the selected authentication method provides only one-way authentication—verifying the
Responder to the Initiator—then there is no benefit in selecting a pattern more complex
than `E1S1`. Patterns such as `E1S2` or `E2S2` introduce additional computational and
communication overhead without improving the resulting security.

If the authentication method provides mutual authentication—for example, using [PAKE][3]
or [TLS-PSK][8]—then the use of `E1S2` or `E2S2` becomes appropriate. These patterns
ensure that both the Initiator and the Responder contribute static keys to the
Diffie-Hellman exchange, reinforcing the mutual nature of the derived secret.

### 5.4 Code Output

The format and characteristics of the OTP/OTK values produced by EPHEMSEC are determined
by the parameters `T`, `B`, and `P`.

#### 5.4.1 T – Time Window

`T` defines the duration of a validity window for each generated code, expressed in
seconds. `T` MUST be a positive integer greater than parameter `B`.

#### 5.4.2 B – Encoding Base

`B` specifies the base used for code encoding. Valid values are:

- `10`, `16`, or `32`: Encodes the output using a human-readable digit set, suitable for OTP.  
- `256`: Encodes the output in binary form, suitable for OTK.

#### 5.4.3 P – Code Size

`P` defines the number of digits in the generated code, where each digit is an integer
in the range `[0..B)`. The valid range of P depends on the encoding base B and the
minimum required entropy.

The table below summarizes the minimum and maximum allowed values of P for each
supported base, along with the corresponding entropy range.

| Base | min P | max P | min Entropy | max Entropy |
| ---- | ----- | ----- | ----------- | ----------- |
| 10   | 8     | 15    | 23 bits     | 46 bits     |
| 16   | 7     | 17    | 24 bits     | 64 bits     |
| 32   | 6     | 13    | 25 bits     | 60 bits     |
| 256  | 6     | 65    | 40 bits     | 512 bits    |

### 5.5 Naming Scheme

EPHEMSEC uses a structured naming scheme to identify specific protocol instantiations. A
valid EPHEMSEC name has the following format:

`Kerpass_<Hash>_<ECDH>_<Pattern>_T<T>B<B>P<P>`

For example:

`Kerpass_SHA512_X25519_E1S1_T600B32P9`

Where:

1. `<Hash>` corresponds to the hash function used (Section 5.1), e.g., `SHA512`.  
2. `<ECDH>` denotes the ECDH function used (Section 5.2), e.g., `X25519`.  
3. `<Pattern>` specifies the key exchange pattern (Section 5.3), e.g., `E1S1`.  
5. `T<T>B<B>P<P>` encodes the code output parameters (Section 5.4), with `<T>`, `<B>`,
   and `<P>` replaced by their respective values.


## 6. EPHEMSEC Credentials

EPHEMSEC requires an **enrollment phase** during which the Responder (typically the
authenticator app) registers an account with the Initiator (the relying web
application). Implementations may support various enrollment scenarios depending on
their operational context and security requirements.

This specification does not define a particular enrollment protocol, but it assumes the
following outcomes:

- The Responder registers a static ECDH public key with the Initiator, corresponding to
  a key pair it controls.
- Both parties derive and retain a shared secret (PSK) that will be used in subsequent
  EPHEMSEC operations.

### 6.1 Shared PSK

The **pre-shared key (PSK)** is a byte string shared between the Responder and
Initiator. It is established during the enrollment process and MUST be at least 32 bytes
in length. The PSK is stored by both parties.

### 6.2 Responder Static Key

During enrollment, the Responder generates a static ECDH key pair and transmits the
corresponding public key to the Initiator. The Initiator stores this public key as part
of the Responder’s account data.

### 6.3 Initiator Static Key

The Initiator is required to maintain a static ECDH key pair only when using key
exchange patterns that require an Initiator static key (e.g., E1S2 or E2S2). The
mechanism by which the Responder obtains and establishes trust in the Initiator’s static
public key is out of scope for this specification.

## 7. EPHEMSEC Protocol Overview

This section outlines the overall flow of a complete EPHEMSEC OTP/OTK generation
exchange between an Initiator and a Responder.

It assumes the following preconditions:

- The two parties have agreed on an EPHEMSEC instantiation (see Section 5).
- The Responder has registered an account with the Initiator, including a shared `PSK` and
  necessary public key material (see Section 6).

The protocol operates as a Challenge/Response exchange. The Initiator sends a message to
the Responder containing:

- A `CONTEXT` byte string (e.g., relying party information),
- A freshly generated `INONCE`,
- Its Diffie-Hellman public key(s) as required by the selected key exchange pattern.

> **Note**: The structure and transport of this message are out of scope for this specification.

Upon receiving this challenge, the Responder performs the following steps to compute the
OTP or OTK:

1. **Obtain nonces** (Section 8):  
   - Read or receive `INONCE` from the Initiator,  
   - Generate `PTIME` and extract `SYNCHINT`.

2. **Compute the Diffie-Hellman shared secret `Z`** (Section 9):  
   Based on the agreed key exchange pattern and available keys.

3. **Derive the intermediary secret `ISK`** (Section 10):  
   Using HKDF with `Z`, `PSK`, `CONTEXT`, `SCHEME`, `INONCE`, and `PTIME`.

4. **Generate the OTP or OTK** (Section 11):  
   - The format is determined by the encoding base `B`,  
   - The last digit or byte encodes `SYNCHINT`.

The Responder returns the resulting code to the Initiator.

The Initiator, upon receiving the response, uses the included `SYNCHINT` to reconstruct
`PTIME` and repeat the same derivation steps to validate or use the resulting code.

## 8. Nonce Acquisition

Each EPHEMSEC session uses two distinct nonces contributed independently by the two
parties involved:

- The **Initiator** provides a nonce called `INONCE`, which ensures session uniqueness
  from the Initiator's side.
- The **Responder** provides a time-based nonce called `PTIME`, which captures the
  Responder’s local clock state.

These nonces serve as independent inputs to the intermediary secret derivation process
(see Section 10).

### 8.1 INONCE – Initiator Nonce

The Initiator generates a nonce `INONCE` that contributes to the personalization of the
derived intermediary secret (see Section 9). This value acts as an Initiator-specific
input to ensure uniqueness of each EPHEMSEC execution.

`INONCE` MUST be a byte string of length between 16 and 64 bytes. It MUST be unique for
each run of the EPHEMSEC algorithm, and MUST NOT be reused across authentication
sessions.

The value of `INONCE` is transmitted from the Initiator to the Responder as part of the
authentication request.

### 8.2. PTIME – Responder Time Nonce

The EPHEMSEC Responder derives a pseudo-time value, `PTIME`, from current time reading.
This `PTIME` acts as a Responder contributed nonce and is used in secret derivation
along with an Initiator-contributed nonce.

The challenge is enabling the Initiator to compute the same `PTIME` value as the
Responder, despite minor clock differences. To address this, the Responder includes a
**synchronization hint**, `SYNCHINT`, in the last digit of the generated OTP or OTK.

Given `SYNCHINT`, the Initiator can recover the original `PTIME` as long as clock drift
remains within acceptable bounds.

#### 8.2.1 Inputs

The following parameters are used throughout this section:

- `time`: Current Unix timestamp (seconds since 1970-01-01).
- `T`: Code validity window (see Section 4.4.1).
- `B`: Encoding base (see Section 4.4.2).

#### 8.2.2 Responder Function – `PTime(time) → (PTIME, SYNCHINT)`

This function is executed by the Responder to compute the `PTIME` nonce and the
associated synchronization hint:

```
step = T / (B - 1) # floating point division
PTIME = round(time / step) 
SYNCHINT = PTIME % B
return PTIME, SYNCHINT
```

#### 8.2.3 Initiator Function – `SyncPTime(time, SYNCHINT) → PTIME`

This function is executed by the Initiator to reconstruct the Responder’s PTIME using
its local time and the received SYNCHINT:

```
mintime = time - (T / 2)
step = T / (B - 1) # floating point division
mpt = round(mintime / step)
mphint = mpt % B

Q = mpt // B # integer division
PTIME = Q * B + SYNCHINT

if SYNCHINT < mphint:
    PTIME += B

return PTIME
```

This algorithm works correctly if the clock difference between the Responder and
Initiator is less than T / 2. Outside this range, synchronization will fail, resulting in
mismatched secrets.

KerPass uses a 600-second time window, allowing up to  ±5 minutes clock drift in between
Initiator and Responder.

## 9. Z - Diffie-Hellman Secret Derivation

Each party derives a shared secret `Z` using the Diffie-Hellman key exchange, based on the
agreed EPHEMSEC key exchange pattern (see Section 5.3). Key material is retrieved from
received protocol messages and account credential storage.

The result of the Diffie-Hellman exchange is a byte string `Z`, which is used as part of
the key derivation input (see later sections).

Where ephemeral key pairs are used, they MUST be freshly generated for each execution of
the EPHEMSEC protocol and MUST NOT be reused across sessions.

EPHEMSEC execution MUST be aborted if any required key is missing or invalid.

### 9.1 Initiator E1S1 Z Derivation

Inputs:
- `ei` Initiator ephemeral Keypair
- `Sr` Responder static PublicKey

```
Z = ECDH(ei, Sr)
```

### 9.2 Responder E1S1 Z Derivation

Inputs:
- `sr` Responder static Keypair
- `Ei` Initiator ephemeral PublicKey

```
Z = ECDH(sr, Ei)
```

### 9.3 Initiator E1S2 Z Derivation

Inputs:
- `ei` Initiator ephemeral Keypair
- `si` Initiator static Keypair
- `Sr` Responder static PublicKey

```
Z = ECDH(ei, Sr) || ECDH(si, Sr)
```

### 9.4 Responder E1S2 Z Derivation

Inputs:
- `sr` Responder static Keypair
- `Ei` Initiator ephemeral PublicKey
- `Si` Initiator static PublicKey

```
Z = ECDH(sr, Ei) || ECDH(sr, Si)
```

### 9.5 Initiator E2S2 Z Derivation

Inputs:
- `ei` Initiator ephemeral Keypair
- `si` Initiator static Keypair
- `Er` Responder ephemeral PublicKey
- `Sr` Responder static PublicKey

```
Z = ECDH(ei, Er) || ECDH(si, Sr)
```

### 9.6 Responder E2S2 Z Derivation

Inputs:
- `er` Responder ephemeral Keypair
- `sr` Responder static Keypair
- `Ei` Initiator ephemeral PublicKey
- `Si` Initiator static PublicKey

```
Z = ECDH(er, Ei) || ECDH(sr, Si)
```

## 10. ISK – Intermediary Secret Derivation

EPHEMSEC derives an intermediary secret key `ISK` using the HKDF function (see Section
5.1.1).

### 10.1 Inputs

The function uses the following inputs:

- `CONTEXT`: An implementation-specific byte string (≤ 64 bytes), used to encode
  contextual information (e.g., relying party domain).
- `SCHEME`: A byte string representing the EPHEMSEC instantiation (see Section 5.5).
- `B`: Code encoding base (see Section 5.4.2).
- `P`: Code size (see Section 5.4.3).
- `INONCE`: An Initiator-generated nonce, a byte string between 16 and 64 bytes (see
  Section 8.1).
- `PTIME`: Responder-contributed time nonce (see Section 8.2).
- `PSK`: A shared pre-established secret (≥ 32 bytes) (see Section 6.1).
- `Z`: Diffie-Hellman shared secret derived from the selected key exchange pattern (see
  Section 8).

### 10.2 ISK Derivation

The `ISK` is derived using the following steps:

```
# CONTEXT & SCHEME are used for domain separation
salt = TLV(byte('C'), CONTEXT) || TLV(byte('S'), SCHEME)

ikm = Z || PSK

# INONCE & PTIME are used for output personalization
info = TLV(byte('N'), INONCE) || TLV(byte('T'), BE8(PTIME))

# Output length
if B == 256:
  L = P - 1 # OTK case
else:
  L = 8 # OTP case

ISK = HKDF(salt, ikm, info, L)

return ISK
```

## 11. OTP/OTK Derivation

The intermediate secret key `ISK` computed in Section 9 serves as the final source of
entropy for generating the OTP (one-time password) or OTK (one-time key). The output
format depends on the encoding base `B` (see Section 5.4.2).

### 11.1 Inputs

- `B`: Code encoding base (Section 5.4.2).
- `P`: Code size (Section 5.4.3).
- `PTIME`: Responder-contributed time nonce (Section 8.2).
- `ISK`: Intermediate secret key (Section 9).

### 11.2 OTP Derivation (`B ∈ {10, 16, 32}`)

When `B` is 10, 16, or 32, the code is formatted as an `OTP` composed of `P` digits. The
first `P - 1` digits are derived from `ISK`, and the last digit is a synchronization
hint (`SYNCHINT`) derived from `PTIME`.

`ISK` MUST be exactly 8 bytes long and is interpreted as an unsigned 64-bit integer.

```
# Interpret ISK as a big-endian unsigned integer
maxcode = B ^ (P - 1)
isrc = U64(ISK) % maxcode

# Extract (P - 1) digits in base B
OTP = '' # empty byte string
for i in 0 .. (P - 2):
    digit = byte(isrc % B)
    OTP = digit || OTP
    isrc /= B

# Append 1-digit time synchronization hint
SYNCHINT = byte(PTIME % B)
OTP = OTP || SYNCHINT

return OTP  # byte string of P digits in [0 .. B)
```

**Note**: The result is returned as a sequence of `P` integer digits in base `B`.
Conversion to a human-readable representation (e.g., alphanumeric alphabet) is outside
the scope of this specification.

### 11.3 OTK Derivation (`B = 256`)

When `B` is 256, the output is an opaque binary key. The first `P - 1` bytes are taken
directly from `ISK`, and the last byte encodes the synchronization hint.

```
SYNCHINT = byte(PTIME % 256)
OTK = ISK || SYNCHINT

return OTK  # byte string of length P

```

[1]: https://www.ietf.org/rfc/rfc4226.txt
[2]: https://www.rfc-editor.org/rfc/rfc6238.txt
[3]: https://en.wikipedia.org/wiki/Password-authenticated_key_agreement
[4]: https://play.google.com/store/apps/details?id=com.google.android.apps.authenticator2&hl=en&pli=1
[5]: https://datatracker.ietf.org/doc/html/rfc5869
[6]: https://datatracker.ietf.org/doc/html/rfc7748
[7]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
[8]: https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.9
