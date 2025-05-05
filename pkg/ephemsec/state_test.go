package ephemsec

import (
	"testing"
)

func TestStateConstants(t *testing.T) {
	if maxContext > 255 {
		t.Errorf("maxContext %d > 255, code assumes it fits on 1 byte", maxContext)
	}
	if maxSchemeName > 255 {
		t.Errorf("maxSchemeName %d > 255, code assumes it fits on 1 byte", maxSchemeName)
	}
	if maxNonce > 255 {
		t.Errorf("maxNonce %d > 255, code assumes it fits on 1 byte", maxNonce)
	}
	if maxMessage > 255 {
		t.Errorf("maxMessage %d > 255, code assumes it fits on 1 byte", maxMessage)
	}
}
