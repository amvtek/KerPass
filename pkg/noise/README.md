# README

This package provides a Go implementation of the [Noise Protocol][1] (revision 34),
closely adhering to the specifications.

All documented [Handshake Patterns][2] are pre-registered in the package pattern
registry . You can also define new patterns using the same syntax as in the
specifications. The package supports the [psk][3] and [fallback][4] modifiers as
specified.

All cryptographic algorithms from the specifications are pre-registered, except,
[X448][5] which is omitted due to lack of support in Go's standard crypto libraries.
Additional algorithms can be registered as needed.

[1]: https://noiseprotocol.org/noise.html
[2]: https://noiseprotocol.org/noise.html#handshake-patterns
[3]: https://noiseprotocol.org/noise.html#pattern-modifiers
[4]: https://noiseprotocol.org/noise.html#the-fallback-modifier
[5]: https://en.wikipedia.org/wiki/Curve448
