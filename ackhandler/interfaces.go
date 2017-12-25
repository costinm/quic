package ackhandler

import (
	"time"

	"github.com/costinm/quicgo/internal/protocol"
	"github.com/costinm/quicgo/internal/wire"
)

// SentPacketHandler handles ACKs received for outgoing packets
type SentPacketHandler interface {
	// SentPacket may modify the packet
	SentPacket(packet *Packet) error
	ReceivedAck(ackFrame *wire.AckFrame, withPacketNumber protocol.PacketNumber, encLevel protocol.EncryptionLevel, recvTime time.Time) error
	SetHandshakeComplete()

	SendingAllowed() bool
	GetStopWaitingFrame(force bool) *wire.StopWaitingFrame
	GetLowestPacketNotConfirmedAcked() protocol.PacketNumber
	ShouldSendRetransmittablePacket() bool
	DequeuePacketForRetransmission() (packet *Packet)
	GetLeastUnacked() protocol.PacketNumber

	GetAlarmTimeout() time.Time
	OnAlarm()
}

// ReceivedPacketHandler handles ACKs needed to send for incoming packets
type ReceivedPacketHandler interface {
	ReceivedPacket(packetNumber protocol.PacketNumber, shouldInstigateAck bool) error
	IgnoreBelow(protocol.PacketNumber)

	GetAlarmTimeout() time.Time
	GetAckFrame() *wire.AckFrame
}
