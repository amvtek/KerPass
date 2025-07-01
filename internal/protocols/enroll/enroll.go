package enroll

import (
	"code.kerpass.org/golang/pkg/noise"
)

var noiseCfg noise.Config

func init() {
	err := noiseCfg.Load("Noise_XX_25519_AESGCM_SHA512")
	if nil != err {
		panic(err)
	}
}
