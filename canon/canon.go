// Package canon implements the canonical encoding of the platform:
// deterministic CBOR (RFC 8949, section 4.2.1) restricted to integers, byte
// strings, text strings, arrays, maps with text keys, booleans and null.
//
// Every value has exactly one encoding, so independent implementations
// compute identical hashes. Floating-point numbers, tags and
// indefinite-length items are not allowed.
package canon

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	enc := cbor.CoreDetEncOptions()
	enc.Time = cbor.TimeUnix
	enc.BigIntConvert = cbor.BigIntConvertShortest
	var err error
	if encMode, err = enc.EncMode(); err != nil {
		panic(err)
	}
	decMode, err = cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		TagsMd:            cbor.TagsForbidden,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
		UTF8:              cbor.UTF8RejectInvalid,
		DefaultMapType:    nil,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// Marshal returns the canonical encoding of v. Struct fields are named by
// their cbor tag, or by their json tag if they have no cbor tag.
func Marshal(v any) ([]byte, error) {
	data, err := encMode.Marshal(v)
	if err != nil {
		return nil, err
	}
	// Guard against Go types that encode outside the allowed subset.
	if err := Check(data); err != nil {
		return nil, err
	}
	return data, nil
}

// Unmarshal decodes canonical data into v. It rejects data that is not
// canonical and struct fields that v does not know.
func Unmarshal(data []byte, v any) error {
	if err := Check(data); err != nil {
		return err
	}
	return decMode.Unmarshal(data, v)
}

// Check reports whether data is exactly one item in canonical encoding.
func Check(data []byte) error {
	var v any
	if err := decMode.Unmarshal(data, &v); err != nil {
		return fmt.Errorf("canon: %w", err)
	}
	if err := allowed(v); err != nil {
		return err
	}
	again, err := encMode.Marshal(v)
	if err != nil {
		return fmt.Errorf("canon: %w", err)
	}
	if !bytes.Equal(again, data) {
		return errors.New("canon: encoding is not canonical")
	}
	return nil
}

func allowed(v any) error {
	switch x := v.(type) {
	case nil, bool, uint64, int64, []byte, string:
		return nil
	case big.Int: // an integer below -2^63
		return nil
	case []any:
		for _, e := range x {
			if err := allowed(e); err != nil {
				return err
			}
		}
		return nil
	case map[any]any:
		for k, e := range x {
			if _, ok := k.(string); !ok {
				return errors.New("canon: map key is not a text string")
			}
			if err := allowed(e); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("canon: type %T is not allowed", v)
	}
}

// ToJSON renders canonical data as indented JSON for human inspection. Byte
// strings become hexadecimal text. The rendering is not the reference form
// and cannot be converted back.
func ToJSON(data []byte) ([]byte, error) {
	if err := Check(data); err != nil {
		return nil, err
	}
	var v any
	if err := decMode.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return json.MarshalIndent(jsonValue(v), "", "  ")
}

func jsonValue(v any) any {
	switch x := v.(type) {
	case []byte:
		return hex.EncodeToString(x)
	case big.Int:
		return x.String()
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = jsonValue(e)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k.(string)] = jsonValue(e) //nolint:forcetypeassert // Check allows text keys only
		}
		return out
	default:
		return v
	}
}

// Raw is one canonical item that is kept as encoded.
type Raw = cbor.RawMessage

// SequenceReader reads a CBOR sequence (RFC 8742) of canonical items.
type SequenceReader struct {
	dec *cbor.Decoder
}

// NewSequenceReader returns a reader for the items in r.
func NewSequenceReader(r io.Reader) *SequenceReader {
	return &SequenceReader{dec: decMode.NewDecoder(r)}
}

// Next returns the next item, or io.EOF after the last one.
func (s *SequenceReader) Next() ([]byte, error) {
	var raw cbor.RawMessage
	if err := s.dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("canon: %w", err)
	}
	if err := Check(raw); err != nil {
		return nil, err
	}
	return raw, nil
}
