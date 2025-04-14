package utils

import (
	"encoding/json"
	"reflect"
	"testing"
)

type SomeStruct struct {
	Name string    `json:"name"`
	Key  HexBinary `json:"key"`
}

func TestHexBinarySerialization(t *testing.T) {
	s1 := SomeStruct{Name: "foo", Key: HexBinary{0, 1, 2, 3, 0xfe, 0xff}}
	srzs1, err := json.Marshal(s1)
	if nil != err {
		t.Fatalf("Oops, failed Marshal, got error %v", err)
	}
	s2 := SomeStruct{}
	err = json.Unmarshal(srzs1, &s2)
	if nil != err {
		t.Fatalf("Oops, failed Unmarshal, got error %v", err)
	}
	if !reflect.DeepEqual(s1, s2) {
		t.Errorf("Oops, failed Unmarshal verif, %+v != %+v", s1, s2)
	}
}
