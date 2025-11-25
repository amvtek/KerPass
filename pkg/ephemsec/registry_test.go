package ephemsec_test

import (
	"testing"

	"code.kerpass.org/golang/pkg/ephemsec"
)

func TestRegistry_GetScheme(t *testing.T) {
	scm, err := ephemsec.GetScheme(ephemsec.SHA512_X25519_E1S1_T600B32P9)
	if nil != err {
		t.Fatalf("Failed scheme retrieval, got error %v", err)
	}
	t.Logf("scheme -> %s", scm.Name())
	t.Logf("scheme.T -> %.2f s", scm.T())
}
