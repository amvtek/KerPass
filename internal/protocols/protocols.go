package protocols

import (
	"code.kerpass.org/golang/internal/transport"
)

type Runner interface {
	Run(t transport.T) error
}
