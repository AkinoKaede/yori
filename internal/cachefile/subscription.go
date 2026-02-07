// SPDX-License-Identifier: GPL-3.0-only

package cachefile

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/varbin"
)

// Subscription represents cached subscription data
type Subscription struct {
	Content     []option.Outbound
	LastUpdated time.Time
	LastEtag    string
}

// MarshalBinary implements encoding.BinaryMarshaler
func (s *Subscription) MarshalBinary(ctx context.Context) ([]byte, error) {
	ctx = include.Context(ctx)
	var buffer bytes.Buffer
	buffer.WriteByte(1)
	content, err := json.MarshalContext(ctx, s.Content)
	if err != nil {
		return nil, err
	}
	_, err = varbin.WriteUvarint(&buffer, uint64(len(content)))
	if err != nil {
		return nil, err
	}
	_, err = buffer.Write(content)
	if err != nil {
		return nil, err
	}
	err = binary.Write(&buffer, binary.BigEndian, s.LastUpdated.Unix())
	if err != nil {
		return nil, err
	}
	lastEtagBytes := []byte(s.LastEtag)
	if err := binary.Write(&buffer, binary.BigEndian, uint64(len(lastEtagBytes))); err != nil {
		return nil, err
	}
	if _, err := buffer.Write(lastEtagBytes); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler
func (s *Subscription) UnmarshalBinary(ctx context.Context, data []byte) error {
	ctx = include.Context(ctx)
	reader := bytes.NewReader(data)
	_, err := reader.ReadByte()
	if err != nil {
		return err
	}
	contentLength, err := binary.ReadUvarint(reader)
	if err != nil {
		return err
	}
	content := make([]byte, contentLength)
	_, err = reader.Read(content)
	if err != nil {
		return err
	}
	err = json.UnmarshalContext(ctx, content, &s.Content)
	if err != nil {
		return err
	}
	var lastUpdatedUnix int64
	err = binary.Read(reader, binary.BigEndian, &lastUpdatedUnix)
	if err != nil {
		return err
	}
	s.LastUpdated = time.Unix(lastUpdatedUnix, 0)
	var lastEtagLength uint64
	if err := binary.Read(reader, binary.BigEndian, &lastEtagLength); err != nil {
		return err
	}
	if lastEtagLength > 0 {
		lastEtagBytes := make([]byte, lastEtagLength)
		if _, err := io.ReadFull(reader, lastEtagBytes); err != nil {
			return err
		}
		s.LastEtag = string(lastEtagBytes)
	} else {
		s.LastEtag = ""
	}
	return nil
}
