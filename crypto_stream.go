package quic

import (
	"io"

	"github.com/costinm/quic/internal/flowcontrol"
	"github.com/costinm/quic/internal/protocol"
	"github.com/costinm/quic/internal/wire"
)

type cryptoStreamI interface {
	StreamID() protocol.StreamID
	io.Reader
	io.Writer
	handleStreamFrame(*wire.StreamFrame) error
	popStreamFrame(protocol.ByteCount) *wire.StreamFrame
	closeForShutdown(error)
	hasDataForWriting() bool
	setReadOffset(protocol.ByteCount)
	// methods needed for flow control
	getWindowUpdate() protocol.ByteCount
	handleMaxStreamDataFrame(*wire.MaxStreamDataFrame)
}

type cryptoStream struct {
	*stream
}

var _ cryptoStreamI = &cryptoStream{}

func newCryptoStream(sender streamSender, flowController flowcontrol.StreamFlowController, version protocol.VersionNumber) cryptoStreamI {
	str := newStream(version.CryptoStreamID(), sender, flowController, version)
	return &cryptoStream{str}
}

// SetReadOffset sets the read offset.
// It is only needed for the crypto stream.
// It must not be called concurrently with any other stream methods, especially Read and Write.
func (s *cryptoStream) setReadOffset(offset protocol.ByteCount) {
	s.receiveStream.readOffset = offset
	s.receiveStream.frameQueue.readPosition = offset
}

func (s *cryptoStream) hasDataForWriting() bool {
	s.sendStream.mutex.Lock()
	hasData := s.sendStream.dataForWriting != nil
	s.sendStream.mutex.Unlock()
	return hasData
}
