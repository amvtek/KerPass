package noise

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"code.kerpass.org/golang/internal/utils"
)

func TestShowPatternTable(t *testing.T) {
	entries := utils.RegistryEntries(patternRegistry)
	lines := make([]string, 0, 1+2*len(entries))
	for k, p := range entries {
		lines = append(lines, fmt.Sprintf("---\n%s:", k))
		lines = append(lines, p.Dsl())
	}
	t.Logf("patternRegistry >\n%s", strings.Join(lines, "\n"))
}

func TestNewPattern(t *testing.T) {
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
				initspecs: [2][]initSpec{[]initSpec{}, []initSpec{}},
				premsgs: [2]msgPtrn{
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
				initspecs: [2][]initSpec{
					[]initSpec{
						{token: "s", hash: true, size: 1},
						{token: "rs", hash: true, size: 1},
					},
					[]initSpec{
						{token: "rs", hash: true, size: 1},
						{token: "s", hash: true, size: 1},
					},
				},
				premsgs: [2]msgPtrn{
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
			dsl: `
			<- s
			...
			-> e, es, s, ss
			<- e, ee, se
			`,
			expect: HandshakePattern{
				initspecs: [2][]initSpec{
					[]initSpec{
						{token: "rs", hash: true, size: 1},
						{token: "s", hash: false, size: 1},
					},
					[]initSpec{
						{token: "s", hash: true, size: 1},
						{token: "verifiers", size: 1},
					},
				},
				premsgs: [2]msgPtrn{
					{sender: "->", tokens: nil},
					{sender: "<-", tokens: []string{"s"}},
				},
				msgs: []msgPtrn{
					{sender: "->", tokens: []string{"e", "es", "s", "ss"}},
					{sender: "<-", tokens: []string{"e", "ee", "se"}},
				},
			},
		},
		{
			dsl: `
			<- s
			...
			-> e, es, s, ss, psk
			<- e, ee, se, psk
			`,
			expect: HandshakePattern{
				initspecs: [2][]initSpec{
					[]initSpec{
						{token: "rs", hash: true, size: 1},
						{token: "s", hash: false, size: 1},
						{token: "psk", hash: false, size: 2},
					},
					[]initSpec{
						{token: "s", hash: true, size: 1},
						{token: "psk", hash: false, size: 2},
						{token: "verifiers", hash: false, size: 1},
					},
				},
				premsgs: [2]msgPtrn{
					{sender: "->", tokens: nil},
					{sender: "<-", tokens: []string{"s"}},
				},
				msgs: []msgPtrn{
					{sender: "->", tokens: []string{"e", "es", "s", "ss", "psk"}},
					{sender: "<-", tokens: []string{"e", "ee", "se", "psk"}},
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
				initspecs: [2][]initSpec{
					[]initSpec{
						{token: "s", hash: true, size: 1},
						{token: "rs", hash: true, size: 1},
					},
					[]initSpec{
						{token: "rs", hash: true, size: 1},
						{token: "s", hash: true, size: 1},
					},
				},
				premsgs: [2]msgPtrn{
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
			// dsl is 1 way N
			dsl: `
			<- s
			...
			-> e, es
			`,
			expect: HandshakePattern{
				initspecs: [2][]initSpec{
					[]initSpec{
						{token: "rs", hash: true, size: 1},
					},
					[]initSpec{
						{token: "s", hash: true, size: 1},
					},
				},
				premsgs: [2]msgPtrn{
					{sender: "->", tokens: nil},
					{sender: "<-", tokens: []string{"s"}},
				},
				msgs: []msgPtrn{
					{sender: "->", tokens: []string{"e", "es"}},
				},
				oneway: true,
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
	var hsp *HandshakePattern
	for pos, tc := range testcases {
		hsp, err = NewPattern(tc.dsl)
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
		if !reflect.DeepEqual(hsp, &tc.expect) {
			t.Errorf("case #%d: result %+v != %+v", pos, hsp, tc.expect)
		}
	}
}
