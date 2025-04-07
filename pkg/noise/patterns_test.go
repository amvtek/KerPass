package noise

import (
	"reflect"
	"testing"
)

func TestShowPatternTable(t *testing.T) {
	t.Logf("defaultPatternTable -> %+v", defaultPatternTable.entries)
}

func TestParsePattern(t *testing.T) {
	testcases := []struct {
		dsl    string
		fail   bool
		expect HandshakePattern
	}{
		{
			dsl: `
			-> e
			<- e ee
			-> ee
			`,
			expect: HandshakePattern{
				messages: []msgPtrn{
					{sender: "->", tokens: []string{"e"}},
					{sender: "<-", tokens: []string{"e", "ee"}},
					{sender: "->", tokens: []string{"ee"}},
				},
			},
		},
		{
			// dsl has supplementary lines and tabs which should be ignored
			dsl: `
			-> s
			<- s
				...

			-> e, es, ss
			<- e, ee, se
			`,
			expect: HandshakePattern{
				preMessages: []msgPtrn{
					{sender: "->", tokens: []string{"s"}},
					{sender: "<-", tokens: []string{"s"}},
				},
				messages: []msgPtrn{
					{sender: "->", tokens: []string{"e", "es", "ss"}},
					{sender: "<-", tokens: []string{"e", "ee", "se"}},
				},
			},
		},
		{
			// fail as first ee pattern miss right ephemeral key
			dsl: `
			-> s
			<- s
			...
			-> e, ee, ss
			<- e, ee, se
			`,
			fail: true,
		},
		{
			// fail as {->, <-} alternance is not respected
			dsl: `
			-> e
			<- e
			<- ee
			-> ee
			`,
			fail: true,
		},
	}
	for pos, tc := range testcases {
		hsp, err := ParsePatternDSL(tc.dsl)
		if tc.fail {
			if nil == err {
				t.Errorf("case #%d: did not get any error", pos)
			}
			continue
		}
		if nil != err {
			t.Errorf("case #%d: got error %v", pos, err)
			continue
		}
		if !reflect.DeepEqual(hsp, tc.expect) {
			t.Errorf("case #%d: result %+v != %+v", pos, hsp, tc.expect)
		}
	}
}
