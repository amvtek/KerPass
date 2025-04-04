package noise

import (
	"crypto"
	"reflect"
	"slices"
	"testing"
)

func TestHkdfKeyReuse(t *testing.T) {
	algo := crypto.SHA256
	hsz := algo.Size()

	ck := slices.Repeat([]byte{1}, hsz)
	ikm := slices.Repeat([]byte{2}, hsz)

	ckreuse := make([]byte, hsz)
	copy(ckreuse, ck)
	ikmreuse := make([]byte, hsz)
	copy(ikmreuse, ikm)
	err := Hkdf(algo, ckreuse, ikmreuse, ckreuse, ikmreuse)
	if nil != err {
		t.Fatalf("Error when running Hkdf: %v", err)
	}

	dk1 := make([]byte, hsz)
	dk2 := make([]byte, hsz)
	err = Hkdf(algo, ck, ikm, dk1, dk2)
	if nil != err {
		t.Fatalf("Error when running Hkdf: %v", err)
	}

	if !reflect.DeepEqual(ckreuse, dk1) {
		t.Error("ck can not be reused")
	}
	if !reflect.DeepEqual(ikmreuse, dk2) {
		t.Error("ikm can not be reused")
	}

}
