package wire

import (
	"bytes"

	"github.com/costinm/quicgo/internal/protocol"
)

// A Frame in QUIC
type Frame interface {
	Write(b *bytes.Buffer, version protocol.VersionNumber) error
	MinLength(version protocol.VersionNumber) protocol.ByteCount
}
