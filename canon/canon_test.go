package canon

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
)

type sample struct {
	Zebra uint64 `cbor:"zebra"`
	Name  string `json:"name"`
	Data  []byte `cbor:"data"`
	List  []int  `cbor:"list,omitempty"`
}

func TestMarshal(t *testing.T) {
	got, err := Marshal(sample{Zebra: 500, Name: "a", Data: []byte{1, 2}})
	if err != nil {
		t.Fatal(err)
	}
	// Map of 3 pairs, keys sorted bytewise: "data", "name", "zebra".
	// 500 is 0x01f4 in the shortest form.
	want := "a3" + "6464617461" + "420102" + "646e616d65" + "6161" + "657a65627261" + "1901f4"
	if hex.EncodeToString(got) != want {
		t.Fatalf("got %x, want %s", got, want)
	}
	var back sample
	if err := Unmarshal(got, &back); err != nil {
		t.Fatal(err)
	}
	if back.Zebra != 500 || back.Name != "a" || !bytes.Equal(back.Data, []byte{1, 2}) {
		t.Fatalf("round trip: %+v", back)
	}
	// Go maps are sorted too.
	a, _ := Marshal(map[string]int{"b": 1, "a": 2, "aa": 3})
	if hex.EncodeToString(a) != "a3"+"616102"+"616201"+"62616103" {
		t.Fatalf("map: %x", a)
	}
}

func TestMarshalRejectsFloat(t *testing.T) {
	if _, err := Marshal(map[string]any{"x": 1.5}); err == nil {
		t.Fatal("float accepted")
	}
}

func TestCheck(t *testing.T) {
	good := []string{
		"00", "17", "1818", "20", "f4", "f5", "f6", "40", "60",
		"83010203",
		"a2616101616202",
		"3bffffffffffffffff", // -2^64
	}
	for _, h := range good {
		data, _ := hex.DecodeString(h)
		if err := Check(data); err != nil {
			t.Errorf("%s rejected: %v", h, err)
		}
	}
	bad := map[string]string{
		"1817":                   "integer not in shortest form",
		"190001":                 "integer not in shortest form",
		"a2616201616101":         "map keys not sorted",
		"a2616101616102":         "duplicate map key",
		"a10102":                 "integer map key",
		"9f0102ff":               "indefinite-length array",
		"5f4101ff":               "indefinite-length byte string",
		"f93e00":                 "float",
		"fb3ff8000000000000":     "float",
		"c11a514b67b0":           "tag",
		"c249010000000000000000": "bignum tag",
		"f7":                     "undefined",
		"0000":                   "two items",
		"":                       "no item",
		"61ff":                   "invalid UTF-8",
		"8301":                   "truncated",
	}
	for h, why := range bad {
		data, _ := hex.DecodeString(h)
		if err := Check(data); err == nil {
			t.Errorf("%s accepted (%s)", h, why)
		}
	}
}

func TestUnmarshalRejectsUnknownField(t *testing.T) {
	data, _ := Marshal(map[string]int{"zebra": 1, "extra": 2})
	var s sample
	if err := Unmarshal(data, &s); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestToJSON(t *testing.T) {
	data, _ := Marshal(sample{Zebra: 1, Name: "n", Data: []byte{0xab}, List: []int{-1}})
	out, err := ToJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Join(strings.Fields(string(out)), "")
	if s != `{"data":"ab","list":[-1],"name":"n","zebra":1}` {
		t.Fatalf("json: %s", s)
	}
}

func FuzzCheck(f *testing.F) {
	for _, h := range []string{"a2616101616202", "83010203", "1817", "9f0102ff", "c11a514b67b0"} {
		data, _ := hex.DecodeString(h)
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if Check(data) != nil {
			return
		}
		// Canonical data decodes and encodes back to itself.
		var v any
		if err := Unmarshal(data, &v); err != nil {
			t.Fatalf("checked data does not decode: %v", err)
		}
		again, err := Marshal(v)
		if err != nil || !bytes.Equal(again, data) {
			t.Fatalf("round trip of %x gives %x, %v", data, again, err)
		}
		if _, err := ToJSON(data); err != nil {
			t.Fatalf("ToJSON: %v", err)
		}
	})
}

func TestSequenceReader(t *testing.T) {
	a, _ := Marshal([]int{1, 2})
	b, _ := Marshal("x")
	r := NewSequenceReader(bytes.NewReader(append(append([]byte{}, a...), b...)))
	for _, want := range [][]byte{a, b} {
		got, err := r.Next()
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("got %x, %v, want %x", got, err, want)
		}
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("want io.EOF, got %v", err)
	}
	// A non-canonical item and a truncated item are errors, not EOF.
	for _, h := range []string{"1817", "8301"} {
		data, _ := hex.DecodeString(h)
		if _, err := NewSequenceReader(bytes.NewReader(data)).Next(); err == nil || errors.Is(err, io.EOF) {
			t.Errorf("%s: got %v", h, err)
		}
	}
}

// Arrays larger than the library default of 131072 elements are accepted,
// as a large electoral roll needs.
func TestLargeArray(t *testing.T) {
	data, err := Marshal(make([]int, 200000))
	if err != nil {
		t.Fatal(err)
	}
	if err := Check(data); err != nil {
		t.Fatal(err)
	}
}
