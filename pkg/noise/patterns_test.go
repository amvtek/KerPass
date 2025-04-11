package noise

import (
	"reflect"
	"testing"
)

func TestShowPatternTable(t *testing.T) {
	t.Logf("patternRegistry -> %+v", patternRegistry.entries)
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
				premsgs: []msgPtrn{
					{sender: "->"},
					{sender: "<-"},
				},
				msgs: []msgPtrn{
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
				premsgs: []msgPtrn{
					{sender: "->", tokens: []string{"s"}},
					{sender: "<-", tokens: []string{"s"}},
				},
				msgs: []msgPtrn{
					{sender: "->", tokens: []string{"e", "es", "ss"}},
					{sender: "<-", tokens: []string{"e", "ee", "se"}},
				},
			},
		},
		{
			// dsl is in "Bob form", ie initiator is at the right
			dsl: `
			-> s
			<- s
				...

			<- e, se, ss
			-> e, ee, es
			`,
			expect: HandshakePattern{
				premsgs: []msgPtrn{
					{sender: "<-", tokens: []string{"s"}},
					{sender: "->", tokens: []string{"s"}},
				},
				msgs: []msgPtrn{
					{sender: "<-", tokens: []string{"e", "se", "ss"}},
					{sender: "->", tokens: []string{"e", "ee", "es"}},
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

	var err error
	var hsp HandshakePattern
	for pos, tc := range testcases {
		err = hsp.LoadDSL(tc.dsl)
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
