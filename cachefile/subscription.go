// SPDX-License-Identifier: GPL-3.0-only

package cachefile

import (
	"bytes"
	"encoding/gob"
	"time"

	"github.com/sagernet/sing-box/option"
)

// Subscription represents cached subscription data
type Subscription struct {
	Content     []option.Outbound
	LastUpdated time.Time
	LastEtag    string
}

// MarshalBinary implements encoding.BinaryMarshaler
func (s *Subscription) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	// Encode struct fields
	if err := enc.Encode(s.Content); err != nil {
		return nil, err
	}
	if err := enc.Encode(s.LastUpdated); err != nil {
		return nil, err
	}
	if err := enc.Encode(s.LastEtag); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler
func (s *Subscription) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)
	dec := gob.NewDecoder(buf)

	// Decode struct fields
	if err := dec.Decode(&s.Content); err != nil {
		return err
	}
	if err := dec.Decode(&s.LastUpdated); err != nil {
		return err
	}
	if err := dec.Decode(&s.LastEtag); err != nil {
		return err
	}

	return nil
}
