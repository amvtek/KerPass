package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
	"unicode"

	"code.kerpass.org/golang/internal/algos"
	"code.kerpass.org/golang/pkg/ephemsec"
)

const usageFmt = `
Command Usage: %s [Flags]
  Generate KerPass EPHEMSEC test vectors.

Flags:
------
`

var (
	defaultCodes = []string{"T400B10P8", "T500B16P9", "T600B32P9", "T550B256P33", "T1024B256P64"}
	codeRe       = regexp.MustCompile(`T[0-9]+B(?:10|16|32|256)P[0-9]+`)
)

type Cmd struct {
	Out     *json.Encoder
	Schemes []string
	Repeat  int
}

func parseFlags(progname string, args []string) *Cmd {
	cmd := Cmd{}

	flags := flag.NewFlagSet(progname, flag.ExitOnError)
	flags.Usage = func() {
		fmt.Fprintf(os.Stderr, usageFmt, path.Base(progname))
		flags.PrintDefaults()
	}

	var outPath string
	flags.StringVar(&outPath, "o", "-", `path where to save the generated vectors`)

	var hashes []string
	const hashDoc = `
	Secure Hash algorithm name.
	Add more than 1 by repeating this option.
	Default to all supported Hashes %+v.
	`
	flags.Func("sh", dedent(fmt.Sprintf(hashDoc, algos.ListHashes())), func(v string) error {
		_, err := algos.GetHash(v)
		if nil == err {
			hashes = append(hashes, v)
		}
		return err
	})

	var curves []string
	const curveDoc = `
	ECDH elliptic curve Diffie-Helmann function name.
	Add more than 1 by repeating this option.
	Defaults to all supported Curves %+v.
	`
	flags.Func("dh", dedent(fmt.Sprintf(curveDoc, algos.ListCurves())), func(v string) error {
		_, err := algos.GetCurve(v)
		if nil == err {
			curves = append(curves, v)
		}
		return err
	})

	var codes []string
	const codeDoc = `
	OTP/OTK encoding pattern of form T600B32P9.
	Add more than 1 by repeating this option.
	Defaults to %+v.
	`
	flags.Func("pa", dedent(fmt.Sprintf(codeDoc, defaultCodes)), func(v string) error {
		matched := codeRe.FindString(v)
		if "" == matched {
			return fmt.Errorf("Invalid code pattern %s", v)
		}
		codes = append(codes, matched)
		return nil
	})

	var repeat uint
	flags.UintVar(&repeat, "n", 10, `number of vectors to generate for each scheme`)

	flags.Parse(args)

	// set cmd.Out
	var err error
	var outFile *os.File
	if "-" != outPath {
		outFile, err = os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if nil != err {
			log.Fatalf("Failed opening %s, got error %v", outPath, err)
		}
	} else {
		outFile = os.Stdout
	}
	enc := json.NewEncoder(outFile)
	enc.SetIndent("", "  ")
	cmd.Out = enc

	// set cmd.Schemes
	if len(hashes) == 0 {
		hashes = algos.ListHashes()
	}
	if len(curves) == 0 {
		curves = algos.ListCurves()
	}
	if len(codes) == 0 {
		codes = defaultCodes
	}
	cmd.Schemes = makeSchemeList(hashes, curves, codes)

	// set cmd.Repeat
	cmd.Repeat = int(repeat)

	return &cmd
}

func main() {
	cmd := parseFlags(os.Args[0], os.Args[1:])

	var err error
	var vectors []ephemsec.TestVector
	for _, schemename := range cmd.Schemes {
		for _ = range cmd.Repeat {
			vector := ephemsec.TestVector{}
			err = fillVector(schemename, &vector)
			if nil != err {
				log.Fatalf("Failed generating TestVector, got error %v", err)
			}
			vectors = append(vectors, vector)
		}
	}
	err = cmd.Out.Encode(vectors)
	if nil != err {
		log.Fatalf("Failed serializing []TestVector, got error %v", err)
	}
}

func dedent(multilines string) string {
	var sb strings.Builder
	for line := range strings.Lines(strings.TrimRightFunc(multilines, unicode.IsSpace)) {
		sb.WriteString(strings.TrimLeftFunc(line, unicode.IsSpace))
	}
	return sb.String()
}

func makeSchemeList(hashes, curves, codes []string) []string {
	var schemes []string
	keyexs := []string{"E1S1", "E1S2", "E2S2"}
	for _, hash := range hashes {
		for _, curve := range curves {
			for _, keyex := range keyexs {
				for _, code := range codes {
					schemes = append(
						schemes,
						fmt.Sprintf("Kerpass_%s_%s_%s_%s", hash, curve, keyex, code),
					)
				}
			}
		}
	}
	return schemes
}
