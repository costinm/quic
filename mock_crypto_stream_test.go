// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/lucas-clemente/quic-go (interfaces: CryptoStream)

// Package quic is a generated GoMock package.
package quic

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	protocol "github.com/costinm/quicgo/internal/protocol"
	wire "github.com/costinm/quicgo/internal/wire"
)

// MockCryptoStream is a mock of CryptoStream interface
type MockCryptoStream struct {
	ctrl     *gomock.Controller
	recorder *MockCryptoStreamMockRecorder
}

// MockCryptoStreamMockRecorder is the mock recorder for MockCryptoStream
type MockCryptoStreamMockRecorder struct {
	mock *MockCryptoStream
}

// NewMockCryptoStream creates a new mock instance
func NewMockCryptoStream(ctrl *gomock.Controller) *MockCryptoStream {
	mock := &MockCryptoStream{ctrl: ctrl}
	mock.recorder = &MockCryptoStreamMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockCryptoStream) EXPECT() *MockCryptoStreamMockRecorder {
	return m.recorder
}

// Read mocks base method
func (m *MockCryptoStream) Read(arg0 []byte) (int, error) {
	ret := m.ctrl.Call(m, "Read", arg0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Read indicates an expected call of Read
func (mr *MockCryptoStreamMockRecorder) Read(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Read", reflect.TypeOf((*MockCryptoStream)(nil).Read), arg0)
}

// StreamID mocks base method
func (m *MockCryptoStream) StreamID() protocol.StreamID {
	ret := m.ctrl.Call(m, "StreamID")
	ret0, _ := ret[0].(protocol.StreamID)
	return ret0
}

// StreamID indicates an expected call of StreamID
func (mr *MockCryptoStreamMockRecorder) StreamID() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "StreamID", reflect.TypeOf((*MockCryptoStream)(nil).StreamID))
}

// Write mocks base method
func (m *MockCryptoStream) Write(arg0 []byte) (int, error) {
	ret := m.ctrl.Call(m, "Write", arg0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Write indicates an expected call of Write
func (mr *MockCryptoStreamMockRecorder) Write(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Write", reflect.TypeOf((*MockCryptoStream)(nil).Write), arg0)
}

// closeForShutdown mocks base method
func (m *MockCryptoStream) closeForShutdown(arg0 error) {
	m.ctrl.Call(m, "closeForShutdown", arg0)
}

// closeForShutdown indicates an expected call of closeForShutdown
func (mr *MockCryptoStreamMockRecorder) closeForShutdown(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "closeForShutdown", reflect.TypeOf((*MockCryptoStream)(nil).closeForShutdown), arg0)
}

// getWindowUpdate mocks base method
func (m *MockCryptoStream) getWindowUpdate() protocol.ByteCount {
	ret := m.ctrl.Call(m, "getWindowUpdate")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// getWindowUpdate indicates an expected call of getWindowUpdate
func (mr *MockCryptoStreamMockRecorder) getWindowUpdate() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "getWindowUpdate", reflect.TypeOf((*MockCryptoStream)(nil).getWindowUpdate))
}

// handleMaxStreamDataFrame mocks base method
func (m *MockCryptoStream) handleMaxStreamDataFrame(arg0 *wire.MaxStreamDataFrame) {
	m.ctrl.Call(m, "handleMaxStreamDataFrame", arg0)
}

// handleMaxStreamDataFrame indicates an expected call of handleMaxStreamDataFrame
func (mr *MockCryptoStreamMockRecorder) handleMaxStreamDataFrame(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "handleMaxStreamDataFrame", reflect.TypeOf((*MockCryptoStream)(nil).handleMaxStreamDataFrame), arg0)
}

// handleStreamFrame mocks base method
func (m *MockCryptoStream) handleStreamFrame(arg0 *wire.StreamFrame) error {
	ret := m.ctrl.Call(m, "handleStreamFrame", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// handleStreamFrame indicates an expected call of handleStreamFrame
func (mr *MockCryptoStreamMockRecorder) handleStreamFrame(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "handleStreamFrame", reflect.TypeOf((*MockCryptoStream)(nil).handleStreamFrame), arg0)
}

// popStreamFrame mocks base method
func (m *MockCryptoStream) popStreamFrame(arg0 protocol.ByteCount) (*wire.StreamFrame, bool) {
	ret := m.ctrl.Call(m, "popStreamFrame", arg0)
	ret0, _ := ret[0].(*wire.StreamFrame)
	ret1, _ := ret[1].(bool)
	return ret0, ret1
}

// popStreamFrame indicates an expected call of popStreamFrame
func (mr *MockCryptoStreamMockRecorder) popStreamFrame(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "popStreamFrame", reflect.TypeOf((*MockCryptoStream)(nil).popStreamFrame), arg0)
}

// setReadOffset mocks base method
func (m *MockCryptoStream) setReadOffset(arg0 protocol.ByteCount) {
	m.ctrl.Call(m, "setReadOffset", arg0)
}

// setReadOffset indicates an expected call of setReadOffset
func (mr *MockCryptoStreamMockRecorder) setReadOffset(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "setReadOffset", reflect.TypeOf((*MockCryptoStream)(nil).setReadOffset), arg0)
}
