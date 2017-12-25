package flowcontrol

import (
	"fmt"

	"github.com/costinm/quic/congestion"
	"github.com/costinm/quic/internal/protocol"
	"github.com/costinm/quic/internal/utils"
	"github.com/costinm/quic/qerr"
)

type connectionFlowController struct {
	baseFlowController
}

var _ ConnectionFlowController = &connectionFlowController{}

// NewConnectionFlowController gets a new flow controller for the connection
// It is created before we receive the peer's transport paramenters, thus it starts with a sendWindow of 0.
func NewConnectionFlowController(
	receiveWindow protocol.ByteCount,
	maxReceiveWindow protocol.ByteCount,
	rttStats *congestion.RTTStats,
) ConnectionFlowController {
	return &connectionFlowController{
		baseFlowController: baseFlowController{
			rttStats:             rttStats,
			receiveWindow:        receiveWindow,
			receiveWindowSize:    receiveWindow,
			maxReceiveWindowSize: maxReceiveWindow,
		},
	}
}

func (c *connectionFlowController) SendWindowSize() protocol.ByteCount {
	return c.baseFlowController.sendWindowSize()
}

// IncrementHighestReceived adds an increment to the highestReceived value
func (c *connectionFlowController) IncrementHighestReceived(increment protocol.ByteCount) error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	c.highestReceived += increment
	if c.checkFlowControlViolation() {
		return qerr.Error(qerr.FlowControlReceivedTooMuchData, fmt.Sprintf("Received %d bytes for the connection, allowed %d bytes", c.highestReceived, c.receiveWindow))
	}
	return nil
}

func (c *connectionFlowController) GetWindowUpdate() protocol.ByteCount {
	c.mutex.Lock()
	oldWindowSize := c.receiveWindowSize
	offset := c.baseFlowController.getWindowUpdate()
	if oldWindowSize < c.receiveWindowSize {
		utils.Debugf("Increasing receive flow control window for the connection to %d kB", c.receiveWindowSize/(1<<10))
	}
	c.mutex.Unlock()
	return offset
}

// EnsureMinimumWindowSize sets a minimum window size
// it should make sure that the connection-level window is increased when a stream-level window grows
func (c *connectionFlowController) EnsureMinimumWindowSize(inc protocol.ByteCount) {
	c.mutex.Lock()
	if inc > c.receiveWindowSize {
		c.receiveWindowSize = utils.MinByteCount(inc, c.maxReceiveWindowSize)
		c.startNewAutoTuningEpoch()
	}
	c.mutex.Unlock()
}
