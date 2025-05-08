package ephemsec

const (
	maxHashSize      = 64
	minHashSize      = 32
	maxPSK           = 64
	minPSK           = 32
	maxContext       = 64
	maxSchemeName    = 64
	maxContextBuffer = maxContext + maxSchemeName + 16
	maxNonce         = 64
	minNonce         = 16
	maxMessage       = 128
	maxIKM           = 64 * 4
	maxInfo          = maxNonce + 16
	maxZero          = 512
	missing          = -1
	markContext      = byte('C')
	markNonce        = byte('N')
	markPTime        = byte('T')
	markMessage      = byte('M')
	markSchemeName   = byte('S')
)
