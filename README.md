# README

KerPass is a one time password credential that can be used with [PAKE][1] algorithms to
establish mutually authenticated connections without depending on external certificate
authorities.

## Project Goals
* Delivers open specifications for KerPass OTP/OTK credential, Trustchain decentralized
  PKI, User Card application, User Agent application, Authentication Server and
  Application Tunnel Server.
* Delivers a reference implementation of the specifications allowing to demo securing a
  browser application.

## Software development
* Main language we use currently is golang, we value its wide standard library and its
  deployability.

## FAQs

1. Why KerPass when we have [WebAuthn][2] ?

KerPass focus on **mutual** User <-> Service authentication where as [WebAuthn][2]
provides a solution for User -> Service authentication. KerPass does not depend on Web
PKI for establishing trust.

2. Are One Time Password still relevant ?

We believe they are, hopefully this modernization effort will demonstrate that we have
been underestimating them. 

[1]: https://en.wikipedia.org/wiki/Password-authenticated_key_agreement
[2]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Authentication_API


