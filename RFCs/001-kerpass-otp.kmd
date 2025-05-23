---
title: "KerPass EPHEMSEC One-Time Password Algorithm"
abbrev: "EPHEMSEC"
docname: draft-mvieuille-kerpass-ephemsec-00
date: 2025-05-20
ipr: trust200902
keyword: Internet-Draft
workgroup: Individual Submission
category: info
stand_alone: yes 

author:
 -
    name: Marc Vieuille
    email: marc.vieuille@polytechnique.org

informative:
  RFC4226:
  RFC5869:
  RFC6238:
  RFC7748:
  SP80056:
    target: "https://bib.ietf.org/public/rfc/bibxml-nist/reference.NIST.SP.800-56Ar3.xml"
    title: ""
  NIST56A:
    title: "Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography"
    author:
      -
        ins: E. Barker
        name: Elaine Barker
      -
        ins: L. Chen
        name: Lily Chen
      -
        ins: A. Roginsky
        name: Allen Roginsky
      -
        ins: R. Davis
        name: Richard Davis
    date: 2018-04
    seriesinfo:
      NIST: Special Publication 800-56A Revision 3
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf

--- abstract

This document specifies KerPass EPHEMSEC, an algorithm for generating time-synchronized
one-time passwords (OTPs) or one-time keys (OTKs). Unlike traditional OTP algorithms
that rely solely on static shared secret credentials, EPHEMSEC derives one-time secrets
by combining ephemeral secrets established via Diffie-Hellman key exchange with
account-specific static secrets. The algorithm supports incorporating context data into
secret generation and embeds a time synchronization hint in each OTP/OTK. These
enhancements improve security by preventing user impersonation even after server
credential compromise and enable context-binding to resist phishing and MITM attacks.
Unlike traditional OTP algorithms, EPHEMSEC supports automatic resynchronization, making
the generated OTPs compatible with Password-Authenticated Key Exchange protocols and
allowing EPHEMSEC OTKs to serve as primary credentials in TLS-PSK protocol
implementations.

--- middle

# Introduction

The primary goal of the KerPass project is to develop an authentication solution in
which a user's smartphone securely hosts credentials compatible with the **KerPass
EPHEMSEC** algorithm, as specified in this document.

The concept of leveraging smartphones as secure authentication devices is well
established. For instance, numerous authenticator apps exist today that implement
one-time password (OTP) generation using the algorithm defined in {{RFC4226}}.

While such applications are simple to use and widely available, they have had limited
impact on the security of web-based applications. Several factors contribute to this
limited success:

1. The design of traditional authenticator apps does not address specific security
   challenges of web applications. In particular, modern web browsers do not provide a
   trusted input interface for entering authentication data, making users vulnerable to
   phishing attacks that capture credentials.
2. Deployment of the corresponding authentication servers introduces additional risks,
   as the stored credentials can be used to impersonate users if compromised.

Traditional OTP systems, such as those specified in {{RFC4226}}, focus primarily on
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

# Functions and Notation

This section defines notation and helper functions used throughout the specification.

- `||`: Denotes byte string concatenation.

- `byte(v)`: Converts an integer or single-character input `v` to a one-byte string.

- `size(bs)`: Returns the length of byte string `bs`, as an integer.

- `BE8(v)`: Returns the 8-byte big-endian encoding of unsigned integer `v`.

- `U64(bs)`: Converts an 8-byte string `bs` into an unsigned 64-bit integer, using
  big-endian interpretation.

- `TLV(tag, bs)`: Constructs a Tag-Length-Value encoding. Returns `byte(tag) || byte(size(bs)) || bs` where:
    - `tag`: An integer identifier in the range 0–255
    - `bs`: A byte string with length ≤ 255 bytes

# EPHEMSEC Roles

EPHEMSEC distinguishes two roles: Initiator & Responder.

## Initiator Role {#initiator}

This role is normally assigned to relying web application.

## Responder Role {#responder}

This role is normally assigned to authenticator application.

# EPHEMSEC Parametrization {#instantation}

Each EPHEMSEC protocol instance is characterized by its selection of cryptographic
primitives and operational parameters. These include:

- A secure hash function,  
- An elliptic-curve Diffie-Hellman (ECDH) function,  
- A key exchange pattern defining key contributions from the parties,  
- Code output parameters specifying how the OTP/OTK values are formatted.

## Hash Function {#Hash}

The hash function MUST be cryptographically secure (e.g., SHA-512) with digest length
between 32 and 64 bytes. . This hash function is used to instantiate the HKDF key
derivation function, as specified in {{RFC5869}}.

### `HKDF(salt, ikm, info, L) → byte[L]` Function {#HKDF}

This function follows the specification in {{RFC5869}}.

- `salt`, `ikm`, and `info` are arbitrary-length byte strings.  
- `L` is a positive integer indicating the desired output length in bytes.  
- The function returns a byte string of length `L`.

## `ECDH(privKey, PubKey) → byte[DHLEN]` Function {#ECDH}

This function performs an Elliptic-Curve Diffie-Hellman (ECDH) key agreement over a
specified elliptic curve group, producing a shared secret of fixed length `DHLEN`.

- `privKey`: A private key from an elliptic curve key pair.  
- `PubKey`: A public key from the same elliptic curve group.

The function computes a shared secret using the standard ECDH primitive associated with
the curve in use. The result is a byte string of length `DHLEN`. The specific behavior,
including internal encoding and validation, is determined by the curve and cryptographic
library in use.

An example of a suitable ECDH function is X25519, as defined in {{RFC7748}},
which yields a 32-byte shared secret.

## Key Exchange Pattern {#pattern}

The key exchange pattern determines which types of keys (ephemeral or static) are
contributed by the Initiator and Responder during the ECDH exchanges.

### E1S1 Pattern {#E1S1}

- Initiator contributes: 1 ephemeral key.  
- Responder contributes: 1 static key.

### E1S2 Pattern {#E1S2}

- Initiator contributes: 1 ephemeral key and 1 static key.  
- Responder contributes: 1 static key.

### E2S2 Pattern {#E2S2}

- Initiator contributes: 1 ephemeral key and 1 static key.  
- Responder contributes: 1 ephemeral key and 1 static key.

### Rationale for Selecting a Key Exchange Pattern

The choice of key exchange pattern should align with the authentication guarantees
provided by the method used to validate the generated OTP or OTK.

If the selected authentication method provides only one-way authentication—verifying the
Responder to the Initiator—then there is no benefit in selecting a pattern more complex
than `E1S1`. Patterns such as `E1S2` or `E2S2` introduce additional computational and
communication overhead without improving the resulting security.

If the authentication method provides mutual authentication—for example, using PAKE
or TLS-PSK—then the use of `E1S2` or `E2S2` becomes appropriate. These patterns
ensure that both the Initiator and the Responder contribute static keys to the
Diffie-Hellman exchange, reinforcing the mutual nature of the derived secret.

## Code Output {#code}

The format and characteristics of the OTP/OTK values produced by EPHEMSEC are determined
by the parameters `T`, `B`, and `P`.

### T – Time Window {#T}

`T` defines the duration of a validity window for each generated code, expressed in
seconds. `T` MUST be a positive integer greater than parameter `B`.

### B – Encoding Base {#B}

`B` specifies the base used for code encoding. Valid values are:

- `10`, `16`, or `32`: Encodes the output using a human-readable digit set, suitable for OTP.  
- `256`: Encodes the output in binary form, suitable for OTK.

### P – Code Size {#P}

`P` defines the number of digits in the generated code, where each digit is an integer
in the range `[0..B)`. The valid range of P depends on the encoding base B and the
minimum required entropy.

The table below summarizes the minimum and maximum allowed values of P for each
supported base, along with the corresponding entropy range.

{: #code-limits title="Code limits"}
| Base | min P | max P | min Entropy | max Entropy |
|:---- |:----- |:----- |:----------- |:----------- |
| 10   | 8     | 15    | 23 bits     | 46 bits     |
| 16   | 7     | 17    | 24 bits     | 64 bits     |
| 32   | 6     | 13    | 25 bits     | 60 bits     |
| 256  | 4     | 65    | 24 bits     | 512 bits    |

## Naming Scheme {#SCHEME}

EPHEMSEC uses a structured naming scheme to identify specific protocol instantiations. A
valid EPHEMSEC name has the following format:

`Kerpass_<Hash>_<ECDH>_<Pattern>_T<T>B<B>P<P>`

For example:

`Kerpass_SHA512_X25519_E1S1_T600B32P9`

Where:

1. `<Hash>` corresponds to the hash function used (see {{Hash}}), e.g., `SHA512`.  
2. `<ECDH>` denotes the ECDH function used (see {{ECDH}}), e.g., `X25519`.  
3. `<Pattern>` specifies the key exchange pattern (see {{pattern}}), e.g., `E1S1`.  
5. `T<T>B<B>P<P>` encodes the code output parameters (see {{code}}), with `<T>`, `<B>`,
   and `<P>` replaced by their respective values.

# EPHEMSEC Credentials {#credentials}

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

## Shared PSK {#PSK}

The **pre-shared key (PSK)** is a byte string shared between the Responder and
Initiator. It is established during the enrollment process and MUST be at least 32 bytes
in length. The PSK is stored by both parties.

## Responder Static Key

During enrollment, the Responder generates a static ECDH key pair and transmits the
corresponding public key to the Initiator. The Initiator stores this public key as part
of the Responder’s account data.

## Initiator Static Key

The Initiator is required to maintain a static ECDH key pair only when using key
exchange patterns that require an Initiator static key (e.g., E1S2 or E2S2). The
mechanism by which the Responder obtains and establishes trust in the Initiator’s static
public key is out of scope for this specification.

# EPHEMSEC Protocol Overview

This section outlines the overall flow of a complete EPHEMSEC OTP/OTK generation
exchange between an Initiator and a Responder.

It assumes the following preconditions:

- The two parties have agreed on an EPHEMSEC instantiation (see {{instantation}}).
- The Responder has registered an account with the Initiator, including a shared `PSK` and
  necessary public key material (see {{credentials}}).

The protocol operates as a Challenge/Response exchange. The Initiator sends a message to
the Responder containing:

- A `CONTEXT` byte string (e.g., relying party information),
- A freshly generated `INONCE`,
- Its Diffie-Hellman public key(s) as required by the selected key exchange pattern.

> **Note**: The structure and transport of this message are out of scope for this specification.

Upon receiving this challenge, the Responder performs the following steps to compute the
OTP or OTK:

1. **Obtain nonces** (see {{nonces}}):  
   - Read or receive `INONCE` from the Initiator,  
   - Generate `PTIME` and extract `SYNCHINT`.

2. **Compute the Diffie-Hellman shared secret `Z`** (see {{Z}}):  
   Based on the agreed key exchange pattern and available keys.

3. **Derive the intermediary secret `ISK`** (see {{ISK}}):  
   Using HKDF with `Z`, `PSK`, `CONTEXT`, `SCHEME`, `INONCE`, and `PTIME`.

4. **Generate the OTP or OTK** (see {{OTP}}):  
   - The format is determined by the encoding base `B`,  
   - The last digit or byte encodes `SYNCHINT`.

The Responder returns the resulting code to the Initiator.

The Initiator, upon receiving the response, uses the included `SYNCHINT` to reconstruct
`PTIME` and repeat the same derivation steps to validate or use the resulting code.

# Nonce Acquisition {#nonces}

Each EPHEMSEC session uses two distinct nonces contributed independently by the two
parties involved:

- The **Initiator** provides a nonce called `INONCE`, which ensures session uniqueness
  from the Initiator's side.
- The **Responder** provides a time-based nonce called `PTIME`, which captures the
  Responder’s local clock state.

These nonces serve as independent inputs to the intermediary secret derivation process
(see 10).

## INONCE – Initiator Nonce {#INONCE}

The Initiator generates a nonce `INONCE` that contributes to the personalization of the
derived intermediary secret (see {{ISK}}). This value acts as an Initiator-specific
input to ensure uniqueness of each EPHEMSEC execution.

`INONCE` MUST be a byte string of length between 16 and 64 bytes. It MUST be unique for
each run of the EPHEMSEC algorithm, and MUST NOT be reused across authentication
sessions.

The value of `INONCE` is transmitted from the Initiator to the Responder as part of the
authentication request.

## PTIME – Responder Time Nonce {#PTIME}

The EPHEMSEC Responder derives a pseudo-time value, `PTIME`, from current time reading.
This `PTIME` acts as a Responder contributed nonce and is used in secret derivation
along with an Initiator-contributed nonce.

The challenge lies in enabling the Initiator to reconstruct the same PTIME value
computed by the Responder, despite clock skew between the two parties. To address this,
the Responder includes a **synchronization hint**, `SYNCHINT`, in the last digit of the
generated OTP or OTK.

Given `SYNCHINT`, the Initiator can recover the original `PTIME` as long as clock drift
remains within acceptable bounds.

### Inputs

The following parameters are used throughout this section:

- `time`: Current Unix timestamp (seconds since 1970-01-01).
- `T`: Code validity window (see {{T}}).
- `B`: Encoding base (see {{B}}).

### Responder Function – `PTime(time) → (PTIME, SYNCHINT)`

This function is executed by the Responder to compute the `PTIME` nonce and the
associated synchronization hint:

~~~ pseudo
step = T / (B - 1) # floating point division
PTIME = round(time / step) 
SYNCHINT = PTIME % B
return PTIME, SYNCHINT
~~~

### Initiator Function – `SyncPTime(time, SYNCHINT) → PTIME`

This function is executed by the Initiator to reconstruct the Responder’s PTIME using
its local time and the received SYNCHINT:

~~~ pseudo
mintime = time - (T / 2)
step = T / (B - 1) # floating point division
mpt = round(mintime / step)
mphint = mpt % B

Q = mpt // B # integer division
PTIME = Q * B + SYNCHINT

if SYNCHINT < mphint:
    PTIME += B

return PTIME
~~~

This algorithm works correctly if the clock difference between the Responder and
Initiator is less than T / 2. Outside this range, synchronization will fail, resulting in
mismatched secrets.

KerPass uses a 600-second time window, allowing up to  ±5 minutes clock drift in between
Initiator and Responder.

# Z - Diffie-Hellman Secret Derivation {#Z}

Each party derives a shared secret `Z` using the Diffie-Hellman key exchange, based on the
agreed EPHEMSEC key exchange pattern (see {{pattern}}). Key material is retrieved from
received protocol messages and account credential storage.

The result of the Diffie-Hellman exchange is a byte string `Z`, which is used as part of
the key derivation input (see later sections).

Where ephemeral key pairs are used, they MUST be freshly generated for each execution of
the EPHEMSEC protocol and MUST NOT be reused across sessions.

EPHEMSEC execution MUST be aborted if any required key is missing or invalid.

## Initiator E1S1 Z Derivation

Inputs:

- `ei` Initiator ephemeral Keypair
- `Sr` Responder static PublicKey

`Z = ECDH(ei, Sr)`

## Responder E1S1 Z Derivation

Inputs:
- `sr` Responder static Keypair
- `Ei` Initiator ephemeral PublicKey

`Z = ECDH(sr, Ei)`

## Initiator E1S2 Z Derivation

Inputs:

- `ei` Initiator ephemeral Keypair
- `si` Initiator static Keypair
- `Sr` Responder static PublicKey

`Z = ECDH(ei, Sr) || ECDH(si, Sr)`

## Responder E1S2 Z Derivation

Inputs:

- `sr` Responder static Keypair
- `Ei` Initiator ephemeral PublicKey
- `Si` Initiator static PublicKey

`Z = ECDH(sr, Ei) || ECDH(sr, Si)`

## Initiator E2S2 Z Derivation

Inputs:

- `ei` Initiator ephemeral Keypair
- `si` Initiator static Keypair
- `Er` Responder ephemeral PublicKey
- `Sr` Responder static PublicKey

`Z = ECDH(ei, Er) || ECDH(si, Sr)`

## Responder E2S2 Z Derivation

Inputs:

- `er` Responder ephemeral Keypair
- `sr` Responder static Keypair
- `Ei` Initiator ephemeral PublicKey
- `Si` Initiator static PublicKey

`Z = ECDH(er, Ei) || ECDH(sr, Si)`

# 10. ISK – Intermediary Secret Derivation {#ISK}

EPHEMSEC derives an intermediary secret key `ISK` using the HKDF function (see
{{HKDF}}).

## 10.1 Inputs {#hkdf-inputs}

The function uses the following inputs:

- `CONTEXT`: An implementation-specific byte string (≤ 64 bytes), used to encode
  contextual information (e.g., login page url).
- `SCHEME`: A byte string representing the EPHEMSEC instantiation (see {{SCHEME}}).
- `B`: Code encoding base (see {{B}}).
- `P`: Code size (see {{P}}).
- `INONCE`: An Initiator-generated nonce, a byte string between 16 and 64 bytes (see
  see {{INONCE}}).
- `PTIME`: Responder-contributed time nonce (see {{PTIME}}).
- `PSK`: A shared pre-established secret (≥ 32 bytes) (see {{PSK}}).
- `Z`: Diffie-Hellman shared secret derived from the selected key exchange pattern (see
  see {{Z}}).

## 10.2 ISK Derivation {#hkdf-use}

The `ISK` is derived using the following steps:

~~~ pseudo
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
~~~

# OTP/OTK Derivation {#OTP}

The intermediate secret key `ISK` computed in {{ISK}} serves as the final source of
entropy for generating the OTP (one-time password) or OTK (one-time key). The output
format depends on the encoding base `B` (see {{B}}).

## Inputs

- `B`: Code encoding base (see {{B}}).
- `P`: Code size (see {{P}}).
- `PTIME`: Responder-contributed time nonce (see {{PTIME}}).
- `ISK`: Intermediate secret key (see {{ISK}}).

## OTP Derivation (`B ∈ {10, 16, 32}`)

When `B` is 10, 16, or 32, the code is formatted as an `OTP` composed of `P` digits. The
first `P - 1` digits are derived from `ISK`, and the last digit is a synchronization
hint (`SYNCHINT`) derived from `PTIME`.

`ISK` MUST be exactly 8 bytes long and is interpreted as an unsigned 64-bit integer.

~~~ pseudo
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
~~~

**Note**: The result is returned as a sequence of `P` integer digits in base `B`.
Conversion to a human-readable representation (e.g., alphanumeric alphabet) is outside
the scope of this specification.

## OTK Derivation (`B = 256`)

When `B` is 256, the output is an opaque binary key. The first `P - 1` bytes are taken
directly from `ISK`, and the last byte encodes the synchronization hint.

~~~ pseudo
SYNCHINT = byte(PTIME % 256)
OTK = ISK || SYNCHINT

return OTK  # byte string of length P
~~~

# Key Exchange Protocol Integration

EPHEMSEC OTPs/OTKs are ephemeral **shared secrets** that can serve as primary
credentials in mutually authenticated key exchange protocols, such as:

- Password-Authenticated Key Exchange (PAKE)
- TLS with Pre-Shared Key authentication (TLS-PSK)

Traditional one-time password algorithms like HOTP, as defined in {{RFC4226}}, are
unsuitable for these protocols due to their reliance on loose synchronization.
Validation servers must compare a received OTP against a range of possible values, which
precludes direct use as cryptographic key material.

EPHEMSEC addresses this limitation by appending a **synchronization digit** to each
OTP/OTK. This digit enables reconstruction of the time-based nonce `PTIME` (see
{{PTIME}}), ensuring that both parties derive identical secrets without relying on
trial-and-error validation.

To use EPHEMSEC outputs as inputs to a key exchange protocol:

1. **Client Preparation**:
   - Append the synchronization digit to the account identifier.
   - Use this composite identifier to initiate the key exchange protocol.

2. **Server Operation**:
   - Extract the synchronization digit from the received identifier.
   - Remove the synchronization digit to recover the base account identifier.
   - Load the corresponding client credentials using the base identifier.
   - Execute the EPHEMSEC algorithm with the received session parameters, credentials,
     and synchronization hint to derive the shared secret.
   - Proceed with the key exchange protocol using the derived secret.

# Security considerations

This section outlines the security properties of the EPHEMSEC algorithm. The analysis
presented here is intended to demonstrate why the protocol is expected to meet its
security goals, based on widely accepted cryptographic assumptions.

This document has not yet undergone comprehensive peer review by the cryptographic and
security communities. The security analysis presented should be considered preliminary,
and implementers should exercise appropriate caution in security-critical deployments
pending further review.

## Adversary Profiles

Two adversary profiles are considered in this analysis:

{: #network-observer}
- **Network Observer**\\
  This adversary has access to all publicly visible data, including the Initiator’s and
  Responder’s static ECDH public keys, session inputs (nonces, ephemeral public keys),
  and outputs (OTPs/OTKs) from previous EPHEMSEC sessions. It does not have access to
  any party’s private credentials.

{: #credential-leak}
- **Credential Leak Attacker**\\
  This adversary has all the capabilities of a Network Observer, and additionally has
  read access to the Initiator’s credential store — specifically the Responder’s shared
  PSKs and static public keys. It does **not** have access to the Initiator’s private
  keys or control over protocol behavior.


## Output Unpredictability of EPHEMSEC

The primary security goal of an OTP/OTK algorithm is to ensure that outputs are
unpredictable — even to attackers with significant passive or partial access.

EPHEMSEC achieves this by combining Diffie-Hellman key exchange and HKDF with
session-specific nonces. Specifically:

1. **Unpredictability of the Shared Secret (`Z`)**\\
   The ECDH-derived shared secret `Z` is indistinguishable from random to any adversary
   lacking private keys, due to the hardness of the Decisional Diffie-Hellman (DDH)
   problem on the chosen curve.

2. **Unpredictability of the HKDF Input (`ikm`)**\\
   The HKDF input key material (`ikm = Z || PSK`) inherits the unpredictability of `Z`.
   Even if the attacker knows the pre-shared key (PSK), the presence of the fresh and
   secret `Z` value ensures `ikm` remains secure.

3. **Security of the Derived Secret (`ISK`)**\\
   HKDF acts as a cryptographically strong pseudorandom function (PRF), meaning its
   outputs — including the intermediary secret `ISK` — are indistinguishable from
   random, provided the HKDF `ikm` secret input is unpredictable. Because each execution
   of EPHEMSEC uses unique nonces and ephemeral keys, the `ISK` value changes with every
   session.

4. **Output Derivation (OTP/OTK)**
   - For OTKs (`B = 256`): `ISK` is directly used, preserving its pseudorandomness.
   - For OTPs (`B ∈ {10, 16, 32}`): `ISK` is converted to digits via modular arithmetic.
     This process introduces bias when `B = 10`, but the bias is mitigated by
     restricting code sizes (`P`) to the ranges specified in {{code-limits}} (see
     {{otp-bias}} for analysis).

5. **Prevention of Replay and Forward Prediction**\\
   The use of unique nonces (`INONCE`, `PTIME`) and ephemeral keys ensures that no two
   executions produce the same output — even for the same account and context. This
   prevents replay attacks and ensures that attackers cannot predict future codes based
   on prior sessions.

As a result, even an attacker who observes multiple sessions (and even possesses some
server-side credentials) cannot derive or guess new OTPs or OTKs, nor can they reuse
prior ones.


## Phishing and MITM Prevention via Context Binding

EPHEMSEC can mitigate web browser phishing and man-in-the-middle (MITM) attacks by binding
cryptographic outputs to authentication context through the `CONTEXT` input (see
{{hkdf-inputs}}). This mechanism enables:

1. **Phishing Resistance**:
   - By embedding the login page URL in `CONTEXT`, the derived OTP/OTK becomes
     domain-specific.
   - An attacker hosting a fake page cannot reuse intercepted codes, as their context
     will differ.

2. **MITM Resistance**:
   - Including the server's TLS certificate hash in `CONTEXT` ensures the OTP/OTK is
     tied to the authenticated connection.
   - A MITM with an invalid certificate cannot generate valid codes.

### The need for a trusted Agent

Context binding alone is **insufficient** to provide Phishing or MITM resistance. 

For Context binding to be efficient, it must be used jointly with a **trusted Agent**
(e.g., a browser extension) that:

- Reliably acquire authentication context (e.g., page URL, certificate)
- Securely inject it into EPHEMSEC's `CONTEXT` parameter
- Resist spoofing or coercion by attackers


## Mutual Authentication

Because the EPHEMSEC Initiator and Responder share a `PSK` (see {{PSK}}), all OTP/OTK
outputs are derived from a secret known to both parties. As a result, these values can
serve as credentials in protocols that support mutual authentication, such as PAKE or
TLS-PSK.

However, when the `E1S1` key exchange pattern is used, the only contribution from the
Initiator is an ephemeral key. In this configuration, the mutuality of the shared secret
relies solely on the `PSK`. If the `PSK` is compromised — for example, by a Credential
Leak Attacker — the attacker can impersonate the Initiator to the Responder.

To mitigate this risk, it is RECOMMENDED that mutual authentication deployments use the
`E1S2` or `E2S2` key exchange patterns. These patterns require the Initiator to
contribute a static ECDH key, ensuring that mutual authentication depends on key
material not accessible to a Credential Leak Attacker. This prevents such an attacker
from successfully impersonating the Initiator.

## Time Synchronization Attacks

EPHEMSEC's time-synchronized nature creates a potential attack vector against the
protocol's availability. The algorithm requires that clock drift between Initiator and
Responder remain within `T/2` seconds for successful PTIME recovery (see {{PTIME}}).

An attacker who can manipulate the time sources or time synchronization mechanisms of
either party may cause authentication failures by forcing clock drift to exceed this
threshold. Such attacks could result in denial of service against the authentication
system.

Future revisions will extend `PTIME` derivation to support event-based counters
alongside time-based synchronization. Setting `T = 0` will enable event-synchronized
OTP/OTK generation using shared counters, while `T > 0` will maintain time-based
operation, allowing applications to choose the synchronization method best suited to
their threat model.

# IANA Considerations

No IANA action is required.


--- back

# OTP Sampling bias {#otp-bias}

Struggling with this, work in progress

## Lemma: Distribution of Remainders in `[0, M)`

Let `m` and `M` be positive integers where `m` ≤ `M`.

For any integer `r` in [0, `m`), the number of integers `v` in [0, `M`) that satisfy `v`
≡ `r` mod `m` is:

1. When `M` is divisible by `m` (`M` mod `m` = 0):
   - Exactly `M`/`m` values for every `r` in [0, `m`)

2. When `M` is not divisible by `m` (`M` mod `m` = `s` where 0 < `s` < `m`):
   - (floor(`M`/`m`) + 1) values for `r` in [0, `s`)
   - floor(`M`/`m`) values for `r` in [`s`, `m`)

### Proof:

Any `v` ≡ `r` mod `m` can be written as `v` = `q`·`m` + `r` where `q` ≥ 0. To keep `v`
in [0, `M`):

`q` ≤ (`M` - 1 - `r`)/`m`

The count of valid `q` values is floor((`M` - 1 - `r`)/`m`) + 1.

When `M` = `k`·`m` (divisible case):
- Count = floor((`k`·`m` - 1 - `r`)/`m`) + 1 = `k` = `M`/`m`

When `M` = `k`·`m` + `s` (non-divisible case):
- For `r` < `s`: count = `k` + 1
- For `r` ≥ `s`: count = `k`
