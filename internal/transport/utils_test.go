package transport

import (
	"bytes"
	"slices"
	"testing"
)

func TestReadLimitTransport(t *testing.T) {
	buf := new(bytes.Buffer)
	lt := NewLimitTransport(RWTransport{R: buf, W: buf})

	var err error
	var wmsg, rmsg []byte
	wmsg = []byte("datagram")

	lt.SetReadLimit(3)
	for i := range 2 {
		err = lt.WriteBytes(wmsg)
		if nil != err {
			t.Fatalf("failed at WriteBytes #%d, got error %v", i, err)
		}
		rmsg, err = lt.ReadBytes()
		if nil != err {
			t.Fatalf("failed at ReadBytes #%d, got error %v", i, err)
		}
		if !slices.Equal(rmsg, wmsg) {
			t.Fatalf("failed rmsg control #%d, %s != %s", i, rmsg, wmsg)
		}
	}
	err = lt.WriteBytes(wmsg)
	if nil != err {
		t.Fatalf("failed at WriteBytes #2, got error %v", err)
	}
	rmsg, err = lt.ReadBytes()
	if nil == err {
		t.Fatal("failed at ReadBytes #2, no error happened")
	}
}

func TestWriteLimitTransport(t *testing.T) {
	buf := new(bytes.Buffer)
	lt := NewLimitTransport(RWTransport{R: buf, W: buf})

	var err error
	wmsg := []byte("datagram")
	lt.SetWriteLimit(5)

	for i := range 4 {
		err = lt.WriteBytes(wmsg)
		if nil != err {
			t.Fatalf("failed at WriteBytes #%d, got error %v", i, err)
		}
	}
	err = lt.WriteBytes(wmsg)
	if nil == err {
		t.Fatal("failed at WriteBytes #4, got no error")
	}
}
