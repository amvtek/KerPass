package noise

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestPatternModifier(t *testing.T) {
	testcases := []struct {
		basePattern string
		modifiers   string
		expectDsl   string
	}{
		{
			basePattern: "N",
			modifiers:   "psk0 psk1",
			expectDsl: `
			<- s
			...
			-> psk e es psk
			`,
		},
		{
			basePattern: "XX",
			modifiers:   "fallback psk2",
			expectDsl: `
			-> e
			...
			<- e ee s es
			-> s se psk
			`,
		},
	}
	for pos, tc := range testcases {
		t.Run(fmt.Sprintf("Case#%d", pos), func(t *testing.T) {
			ptrn := HandshakePattern{}
			err := LoadPattern(tc.basePattern, &ptrn)
			if nil != err {
				t.Fatalf("Failed loading pattern %s", tc.basePattern)
			}
			var md PatternModifier
			for name := range strings.FieldsSeq(tc.modifiers) {
				md, err = GetModifier(name)
				if nil != err {
					t.Fatalf("Failed loading modifier %s", name)
				}
				ptrn, err = md.Modify(ptrn)
				if nil != err {
					t.Fatalf("Failed applying modifier %s", name)
				}
			}
			expectPtrn, err := NewPattern(tc.expectDsl)
			if nil != err {
				t.Fatalf("Oops, failed loading expectDsl")
			}
			if !reflect.DeepEqual(&ptrn, expectPtrn) {
				t.Errorf("Failed expect check, got %+v\n!=\n%+v", &ptrn, expectPtrn)
			}
			t.Logf("ptrn -> %+v", ptrn)
		})
	}
}
