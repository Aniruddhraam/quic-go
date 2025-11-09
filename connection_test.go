package quic

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/ackhandler"
	"github.com/quic-go/quic-go/internal/flowcontrol"
	"github.com/quic-go/quic-go/internal/handshake"
	"github.com/quic-go/quic-go/internal/mocks"
	mockackhandler "github.com/quic-go/quic-go/internal/mocks/ackhandler"
	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/qerr"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"
	"github.com/quic-go/quic-go/testutils/events"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type testConnectionOpt func(*Conn)

func connectionOptCryptoSetup(cs *mocks.MockCryptoSetup) testConnectionOpt {
	return func(conn *Conn) { conn.cryptoStreamHandler = cs }
}

func connectionOptConnFlowController(cfc flowcontrol.ConnectionFlowController) testConnectionOpt {
	return func(conn *Conn) { conn.connFlowController = cfc }
}

func connectionOptTracer(r qlogwriter.Recorder) testConnectionOpt {
	return func(conn *Conn) { conn.qlogger = r }
}

func connectionOptSentPacketHandler(sph ackhandler.SentPacketHandler) testConnectionOpt {
	return func(conn *Conn) { conn.sentPacketHandler = sph }
}

func connectionOptReceivedPacketHandler(rph ackhandler.ReceivedPacketHandler) testConnectionOpt {
	return func(conn *Conn) { conn.receivedPacketHandler = rph }
}

func connectionOptUnpacker(u unpacker) testConnectionOpt {
	return func(conn *Conn) { conn.unpacker = u }
}

func connectionOptSender(s sender) testConnectionOpt {
	return func(conn *Conn) { conn.sendQueue = s }
}

func connectionOptHandshakeConfirmed() testConnectionOpt {
	return func(conn *Conn) {
		conn.handshakeComplete = true
		conn.handshakeConfirmed = true
	}
}

func connectionOptRTT(rtt time.Duration) testConnectionOpt {
	rttStats := utils.NewRTTStats()
	rttStats.UpdateRTT(rtt, 0)
	return func(conn *Conn) { conn.rttStats = rttStats }
}

func connectionOptRetrySrcConnID(rcid protocol.ConnectionID) testConnectionOpt {
	return func(conn *Conn) { conn.retrySrcConnID = &rcid }
}

type testConnection struct {
	conn       *Conn
	connRunner *MockConnRunner
	sendConn   *MockSendConn
	packer     *MockPacker
	destConnID protocol.ConnectionID
	srcConnID  protocol.ConnectionID
	remoteAddr *net.UDPAddr
}

func newServerTestConnection(
	t *testing.T,
	mockCtrl *gomock.Controller,
	config *Config,
	gso bool,
	opts ...testConnectionOpt,
) *testConnection {
	if mockCtrl == nil {
		mockCtrl = gomock.NewController(t)
	}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321}
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	connRunner := NewMockConnRunner(mockCtrl)
	sendConn := NewMockSendConn(mockCtrl)
	sendConn.EXPECT().capabilities().Return(connCapabilities{GSO: gso}).AnyTimes()
	sendConn.EXPECT().RemoteAddr().Return(remoteAddr).AnyTimes()
	sendConn.EXPECT().LocalAddr().Return(localAddr).AnyTimes()
	packer := NewMockPacker(mockCtrl)
	b := make([]byte, 12)
	rand.Read(b)
	origDestConnID := protocol.ParseConnectionID(b[:6])
	srcConnID := protocol.ParseConnectionID(b[6:12])
	ctx, cancel := context.WithCancelCause(context.Background())
	if config == nil {
		config = &Config{DisablePathMTUDiscovery: true}
	}
	wc := newConnection(
		ctx,
		cancel,
		sendConn,
		connRunner,
		origDestConnID,
		nil,
		protocol.ConnectionID{},
		protocol.ConnectionID{},
		srcConnID,
		&protocol.DefaultConnectionIDGenerator{},
		newStatelessResetter(nil),
		populateConfig(config),
		&tls.Config{},
		handshake.NewTokenGenerator(handshake.TokenProtectorKey{}),
		false,
		1337*time.Millisecond,
		nil,
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.Nil(t, wc.testHooks)
	conn := wc.Conn
	conn.packer = packer
	for _, opt := range opts {
		opt(conn)
	}
	return &testConnection{
		conn:       conn,
		connRunner: connRunner,
		sendConn:   sendConn,
		packer:     packer,
		destConnID: origDestConnID,
		srcConnID:  srcConnID,
		remoteAddr: remoteAddr,
	}
}

func newClientTestConnection(
	t *testing.T,
	mockCtrl *gomock.Controller,
	config *Config,
	enable0RTT bool,
	opts ...testConnectionOpt,
) *testConnection {
	if mockCtrl == nil {
		mockCtrl = gomock.NewController(t)
	}
	remoteAddr := &net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 4321}
	localAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	connRunner := NewMockConnRunner(mockCtrl)
	sendConn := NewMockSendConn(mockCtrl)
	sendConn.EXPECT().capabilities().Return(connCapabilities{}).AnyTimes()
	sendConn.EXPECT().RemoteAddr().Return(remoteAddr).AnyTimes()
	sendConn.EXPECT().LocalAddr().Return(localAddr).AnyTimes()
	packer := NewMockPacker(mockCtrl)
	b := make([]byte, 12)
	rand.Read(b)
	destConnID := protocol.ParseConnectionID(b[:6])
	srcConnID := protocol.ParseConnectionID(b[6:12])
	if config == nil {
		config = &Config{DisablePathMTUDiscovery: true}
	}
	conn := newClientConnection(
		context.Background(),
		sendConn,
		connRunner,
		destConnID,
		srcConnID,
		&protocol.DefaultConnectionIDGenerator{},
		newStatelessResetter(nil),
		populateConfig(config),
		&tls.Config{ServerName: "quic-go.net"},
		0,
		enable0RTT,
		false,
		nil,
		utils.DefaultLogger,
		protocol.Version1,
	)
	require.Nil(t, conn.testHooks)
	conn.packer = packer
	for _, opt := range opts {
		opt(conn.Conn)
	}
	return &testConnection{
		conn:       conn.Conn,
		connRunner: connRunner,
		sendConn:   sendConn,
		packer:     packer,
		destConnID: destConnID,
		srcConnID:  srcConnID,
	}
}

func TestConnectionHandleStreamRelatedFrames(t *testing.T) {
	const id protocol.StreamID = 5
	connID := protocol.ConnectionID{}

	tests := []struct {
		name  string
		frame wire.Frame
	}{
		{name: "RESET_STREAM", frame: &wire.ResetStreamFrame{StreamID: id, ErrorCode: 42, FinalSize: 1337}},
		{name: "STOP_SENDING", frame: &wire.StopSendingFrame{StreamID: id, ErrorCode: 42}},
		{name: "MAX_STREAM_DATA", frame: &wire.MaxStreamDataFrame{StreamID: id, MaximumStreamData: 1337}},
		{name: "STREAM_DATA_BLOCKED", frame: &wire.StreamDataBlockedFrame{StreamID: id, MaximumStreamData: 42}},
		{name: "STREAM_FRAME", frame: &wire.StreamFrame{StreamID: id, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}, Offset: 1337}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tc := newServerTestConnection(t, gomock.NewController(t), nil, false)
			data, err := test.frame.Append(nil, protocol.Version1)
			require.NoError(t, err)
			_, _, _, err = tc.conn.handleFrames(data, connID, protocol.Encryption1RTT, nil, monotime.Now())
			require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.StreamStateError})
		})
	}
}

func TestConnectionHandleConnectionFlowControlFrames(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	connFC := flowcontrol.NewConnectionFlowController(0, 0, nil, utils.NewRTTStats(), utils.DefaultLogger)
	require.Zero(t, connFC.SendWindowSize())
	tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptConnFlowController(connFC))
	now := monotime.Now()
	connID := protocol.ConnectionID{}
	// MAX_DATA frame
	_, err := tc.conn.handleFrame(&wire.MaxDataFrame{MaximumData: 1337}, protocol.Encryption1RTT, connID, now)
	require.NoError(t, err)
	require.Equal(t, protocol.ByteCount(1337), connFC.SendWindowSize())
	// DATA_BLOCKED frame
	_, err = tc.conn.handleFrame(&wire.DataBlockedFrame{MaximumData: 1337}, protocol.Encryption1RTT, connID, now)
	require.NoError(t, err)
}

func TestConnectionStatelessReset(t *testing.T) {

	mockCtrl := gomock.NewController(t)
	var eventRecorder events.Recorder
	tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))
	errChan := make(chan error, 1)
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()

	go func() { errChan <- tc.conn.run() }()
	tc.conn.destroy(&StatelessResetError{})

	require.Equal(t,
		[]qlogwriter.Event{qlog.ConnectionClosed{Initiator: qlog.InitiatorLocal, Trigger: qlog.ConnectionCloseTriggerStatelessReset}},
		eventRecorder.Events(qlog.ConnectionClosed{}),
	)

}

func getLongHeaderPacket(t *testing.T, remoteAddr net.Addr, extHdr *wire.ExtendedHeader, data []byte) receivedPacket {
	t.Helper()
	b, err := extHdr.Append(nil, protocol.Version1)
	require.NoError(t, err)
	return receivedPacket{
		remoteAddr: remoteAddr,
		data:       append(b, data...),
		buffer:     getPacketBuffer(),
		rcvTime:    monotime.Now(),
	}
}

func getShortHeaderPacket(t *testing.T, remoteAddr net.Addr, connID protocol.ConnectionID, pn protocol.PacketNumber, data []byte) receivedPacket {
	t.Helper()
	b, err := wire.AppendShortHeader(nil, connID, pn, protocol.PacketNumberLen2, protocol.KeyPhaseOne)
	require.NoError(t, err)
	return receivedPacket{
		remoteAddr: remoteAddr,
		data:       append(b, data...),
		buffer:     getPacketBuffer(),
		rcvTime:    monotime.Now(),
	}
}

func TestConnectionServerInvalidPackets(t *testing.T) {
	t.Run("Retry", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))

		p := getLongHeaderPacket(t,
			tc.remoteAddr,
			&wire.ExtendedHeader{Header: wire.Header{
				Type:             protocol.PacketTypeRetry,
				DestConnectionID: tc.conn.origDestConnID,
				SrcConnectionID:  tc.srcConnID,
				Version:          tc.conn.version,
				Token:            []byte("foobar"),
			}},
			make([]byte, 16), /* Retry integrity tag */
		)
		wasProcessed, err := tc.conn.handleOnePacket(p)
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Header: qlog.PacketHeader{
						PacketType:       qlog.PacketTypeRetry,
						SrcConnectionID:  tc.srcConnID,
						DestConnectionID: tc.conn.origDestConnID,
						Version:          tc.conn.version,
					},
					Raw:     qlog.RawInfo{Length: int(p.Size())},
					Trigger: qlog.PacketDropUnexpectedPacket,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})

	t.Run("version negotiation", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))

		b := wire.ComposeVersionNegotiation(
			protocol.ArbitraryLenConnectionID(tc.srcConnID.Bytes()),
			protocol.ArbitraryLenConnectionID(tc.conn.origDestConnID.Bytes()),
			[]Version{Version1},
		)
		wasProcessed, err := tc.conn.handleOnePacket(receivedPacket{data: b, buffer: getPacketBuffer()})
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
					Raw:     qlog.RawInfo{Length: len(b)},
					Trigger: qlog.PacketDropUnexpectedPacket,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})

	t.Run("unsupported version", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))

		p := getLongHeaderPacket(t,
			tc.remoteAddr,
			&wire.ExtendedHeader{
				Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: 1234},
				PacketNumberLen: protocol.PacketNumberLen2,
			},
			nil,
		)
		wasProcessed, err := tc.conn.handleOnePacket(p)
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Header:  qlog.PacketHeader{Version: 1234},
					Raw:     qlog.RawInfo{Length: int(p.Size())},
					Trigger: qlog.PacketDropUnsupportedVersion,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})

	t.Run("invalid header", func(t *testing.T) {
		mockCtrl := gomock.NewController(t)
		var eventRecorder events.Recorder
		tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))

		p := getLongHeaderPacket(t,
			tc.remoteAddr,
			&wire.ExtendedHeader{
				Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: Version1},
				PacketNumberLen: protocol.PacketNumberLen2,
			},
			nil,
		)
		p.data[0] ^= 0x40 // unset the QUIC bit
		wasProcessed, err := tc.conn.handleOnePacket(p)
		require.NoError(t, err)
		require.False(t, wasProcessed)
		require.Equal(t,
			[]qlogwriter.Event{
				qlog.PacketDropped{
					Header:  qlog.PacketHeader{},
					Raw:     qlog.RawInfo{Length: int(p.Size())},
					Trigger: qlog.PacketDropHeaderParseError,
				},
			},
			eventRecorder.Events(qlog.PacketDropped{}),
		)
	})
}

func TestConnectionClientDrop0RTT(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	var eventRecorder events.Recorder
	tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))

	p := getLongHeaderPacket(t,
		tc.remoteAddr,
		&wire.ExtendedHeader{
			Header:          wire.Header{Type: protocol.PacketType0RTT, Length: 2, Version: protocol.Version1},
			PacketNumberLen: protocol.PacketNumberLen2,
		},
		nil,
	)
	wasProcessed, err := tc.conn.handleOnePacket(p)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:   qlog.PacketType0RTT,
					PacketNumber: protocol.InvalidPacketNumber,
				},
				Raw:     qlog.RawInfo{Length: int(p.Size())},
				Trigger: qlog.PacketDropUnexpectedPacket,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
}

func TestConnectionUnpacking(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	var eventRecorder events.Recorder
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptReceivedPacketHandler(rph),
		connectionOptUnpacker(unpacker),
		connectionOptTracer(&eventRecorder),
	)

	// receive a long header packet
	hdr := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeInitial,
			DestConnectionID: tc.srcConnID,
			Version:          protocol.Version1,
			Length:           1,
		},
		PacketNumber:    0x37,
		PacketNumberLen: protocol.PacketNumberLen1,
	}
	unpackedHdr := *hdr
	unpackedHdr.PacketNumber = 0x1337
	packet := getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	packet.ecn = protocol.ECNCE
	rcvTime := monotime.Now().Add(-10 * time.Second)
	packet.rcvTime = rcvTime
	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(&unpackedPacket{
		encryptionLevel: protocol.EncryptionInitial,
		hdr:             &unpackedHdr,
		data:            []byte{0}, // one PADDING frame
	}, nil)
	gomock.InOrder(
		rph.EXPECT().IsPotentiallyDuplicate(protocol.PacketNumber(0x1337), protocol.EncryptionInitial),
		rph.EXPECT().ReceivedPacket(protocol.PacketNumber(0x1337), protocol.ECNCE, protocol.EncryptionInitial, rcvTime, false),
	)

	wasProcessed, err := tc.conn.handleOnePacket(packet)
	require.NoError(t, err)
	require.True(t, wasProcessed)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketReceived{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeInitial,
					DestConnectionID: tc.srcConnID,
					PacketNumber:     protocol.PacketNumber(0x1337),
					Version:          protocol.Version1,
				},
				Frames: []qlog.Frame{},
				ECN:    qlog.ECNCE,
				Raw:    qlog.RawInfo{Length: int(packet.Size()), PayloadLength: 1},
			},
		},
		eventRecorder.Events(qlog.PacketReceived{}, qlog.PacketDropped{}),
	)
	eventRecorder.Clear()

	// receive a duplicate of this packet
	packet = getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	rph.EXPECT().IsPotentiallyDuplicate(protocol.PacketNumber(0x1337), protocol.EncryptionInitial).Return(true)
	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(&unpackedPacket{
		encryptionLevel: protocol.EncryptionInitial,
		hdr:             &unpackedHdr,
		data:            []byte{0}, // one PADDING frame
	}, nil)
	wasProcessed, err = tc.conn.handleOnePacket(packet)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeInitial,
					DestConnectionID: tc.srcConnID,
					PacketNumber:     protocol.PacketNumber(0x1337),
					Version:          protocol.Version1,
				},
				Raw:     qlog.RawInfo{Length: int(packet.Size()), PayloadLength: 1},
				Trigger: qlog.PacketDropDuplicate,
			},
		},
		eventRecorder.Events(qlog.PacketReceived{}, qlog.PacketDropped{}),
	)
	eventRecorder.Clear()

	// receive a short header packet
	packet = getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, 0x37, nil)
	packet.ecn = protocol.ECT1
	packet.rcvTime = rcvTime
	gomock.InOrder(
		rph.EXPECT().IsPotentiallyDuplicate(protocol.PacketNumber(0x1337), protocol.Encryption1RTT),
		rph.EXPECT().ReceivedPacket(protocol.PacketNumber(0x1337), protocol.ECT1, protocol.Encryption1RTT, rcvTime, false),
	)
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(
		protocol.PacketNumber(0x1337), protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{0} /* PADDING */, nil,
	)
	wasProcessed, err = tc.conn.handleOnePacket(packet)
	require.NoError(t, err)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketReceived{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketType1RTT,
					DestConnectionID: tc.srcConnID,
					PacketNumber:     protocol.PacketNumber(0x1337),
					KeyPhaseBit:      protocol.KeyPhaseZero,
				},
				Raw:    qlog.RawInfo{Length: int(packet.Size())},
				Frames: []qlog.Frame{},
				ECN:    qlog.ECT1,
			},
		},
		eventRecorder.Events(qlog.PacketReceived{}, qlog.PacketDropped{}),
	)
	require.True(t, wasProcessed)
}

func TestConnectionUnpackCoalescedPacket(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	rph := mockackhandler.NewMockReceivedPacketHandler(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	var eventRecorder events.Recorder
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptReceivedPacketHandler(rph),
		connectionOptUnpacker(unpacker),
		connectionOptTracer(&eventRecorder),
	)
	hdr1 := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeInitial,
			DestConnectionID: tc.srcConnID,
			Version:          protocol.Version1,
			Length:           1,
		},
		PacketNumber:    37,
		PacketNumberLen: protocol.PacketNumberLen1,
	}
	hdr2 := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeHandshake,
			DestConnectionID: tc.srcConnID,
			Version:          protocol.Version1,
			Length:           1,
		},
		PacketNumber:    38,
		PacketNumberLen: protocol.PacketNumberLen1,
	}
	// add a packet with a different source connection ID
	incorrectSrcConnID := protocol.ParseConnectionID([]byte{0xa, 0xb, 0xc})
	hdr3 := &wire.ExtendedHeader{
		Header: wire.Header{
			Type:             protocol.PacketTypeHandshake,
			DestConnectionID: incorrectSrcConnID,
			Version:          protocol.Version1,
			Length:           1,
		},
		PacketNumber:    0x42,
		PacketNumberLen: protocol.PacketNumberLen1,
	}
	unpackedHdr1 := *hdr1
	unpackedHdr1.PacketNumber = 1337
	unpackedHdr2 := *hdr2
	unpackedHdr2.PacketNumber = 1338

	packet := getLongHeaderPacket(t, tc.remoteAddr, hdr1, nil)
	firstPacketLen := packet.Size()
	packet2 := getLongHeaderPacket(t, tc.remoteAddr, hdr2, nil)
	packet3 := getLongHeaderPacket(t, tc.remoteAddr, hdr3, nil)
	packet.data = append(packet.data, packet2.data...)
	packet.data = append(packet.data, packet3.data...)
	packet.ecn = protocol.ECT1
	rcvTime := monotime.Now()
	packet.rcvTime = rcvTime

	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(&unpackedPacket{
		encryptionLevel: protocol.EncryptionInitial,
		hdr:             &unpackedHdr1,
		data:            []byte{0}, // one PADDING frame
	}, nil)
	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(&unpackedPacket{
		encryptionLevel: protocol.EncryptionHandshake,
		hdr:             &unpackedHdr2,
		data:            []byte{1}, // one PING frame
	}, nil)
	gomock.InOrder(
		rph.EXPECT().IsPotentiallyDuplicate(protocol.PacketNumber(1337), protocol.EncryptionInitial),
		rph.EXPECT().ReceivedPacket(protocol.PacketNumber(1337), protocol.ECT1, protocol.EncryptionInitial, rcvTime, false),
		rph.EXPECT().IsPotentiallyDuplicate(protocol.PacketNumber(1338), protocol.EncryptionHandshake),
		rph.EXPECT().ReceivedPacket(protocol.PacketNumber(1338), protocol.ECT1, protocol.EncryptionHandshake, rcvTime, true),
	)
	rph.EXPECT().DropPackets(protocol.EncryptionInitial)
	wasProcessed, err := tc.conn.handleOnePacket(packet)
	require.NoError(t, err)
	require.True(t, wasProcessed)

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketReceived{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeInitial,
					DestConnectionID: tc.srcConnID,
					PacketNumber:     protocol.PacketNumber(1337),
					Version:          protocol.Version1,
				},
				Raw:    qlog.RawInfo{Length: int(firstPacketLen), PayloadLength: 1},
				Frames: []qlog.Frame{},
				ECN:    qlog.ECT1,
			},
			qlog.PacketReceived{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeHandshake,
					DestConnectionID: tc.srcConnID,
					PacketNumber:     protocol.PacketNumber(1338),
					Version:          protocol.Version1,
				},
				Raw:    qlog.RawInfo{Length: int(packet2.Size()), PayloadLength: 1},
				Frames: []qlog.Frame{{Frame: &wire.PingFrame{}}},
				ECN:    qlog.ECT1,
			},
			qlog.PacketDropped{
				Header:  qlog.PacketHeader{DestConnectionID: incorrectSrcConnID},
				Raw:     qlog.RawInfo{Length: int(packet3.Size())},
				Trigger: qlog.PacketDropUnknownConnectionID,
			},
		},
		eventRecorder.Events(qlog.PacketReceived{}, qlog.PacketDropped{}),
	)
}

func TestConnectionUnpackFailuresFatal(t *testing.T) {
	t.Run("other errors", func(t *testing.T) {
		require.ErrorIs(t,
			testConnectionUnpackFailureFatal(t, &qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError}),
			&qerr.TransportError{ErrorCode: qerr.ConnectionIDLimitError},
		)
	})

	t.Run("invalid reserved bits", func(t *testing.T) {
		require.ErrorIs(t,
			testConnectionUnpackFailureFatal(t, wire.ErrInvalidReservedBits),
			&qerr.TransportError{ErrorCode: qerr.ProtocolViolation},
		)
	})
}

func testConnectionUnpackFailureFatal(t *testing.T, unpackErr error) error {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptUnpacker(unpacker),
	)

	tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any())
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).Return(protocol.PacketNumber(0), protocol.PacketNumberLen(0), protocol.KeyPhaseBit(0), nil, unpackErr)
	tc.packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), protocol.Version1).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any())
	tc.conn.handlePacket(getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, 0x42, nil))

	select {
	case err := <-errChan:
		require.Error(t, err)
		return err
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	return nil
}

func TestConnectionMaxUnprocessedPackets(t *testing.T) {

	mockCtrl := gomock.NewController(t)
	var eventRecorder events.Recorder
	tc := newServerTestConnection(t, mockCtrl, nil, false, connectionOptTracer(&eventRecorder))

	for range protocol.MaxConnUnprocessedPackets {
		// nothing here should block
		tc.conn.handlePacket(receivedPacket{data: []byte("foobar")})
	}
	tc.conn.handlePacket(receivedPacket{data: []byte("foobar")})

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Raw:     qlog.RawInfo{Length: 6},
				Trigger: qlog.PacketDropDOSPrevention,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)

}

func TestConnectionHandshakeIdleTimeout(t *testing.T) {

	mockCtrl := gomock.NewController(t)
	var eventRecorder events.Recorder
	tc := newServerTestConnection(t,
		mockCtrl,
		&Config{HandshakeIdleTimeout: 7 * time.Second},
		false,
		connectionOptTracer(&eventRecorder),
		func(c *Conn) { c.creationTime = monotime.Now().Add(-20 * time.Second) },
	)
	tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).AnyTimes()
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, &HandshakeTimeoutError{})
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.ConnectionClosed{
				Initiator: qlog.InitiatorLocal,
				Trigger:   qlog.ConnectionCloseTriggerIdleTimeout,
			},
		},
		eventRecorder.Events(qlog.ConnectionClosed{}),
	)

}

func TestConnectionTransportParameters(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	var eventRecorder events.Recorder
	connFC := flowcontrol.NewConnectionFlowController(0, 0, nil, utils.NewRTTStats(), utils.DefaultLogger)
	require.Zero(t, connFC.SendWindowSize())
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(&eventRecorder),
		connectionOptConnFlowController(connFC),
	)
	_, err := tc.conn.OpenStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})
	_, err = tc.conn.OpenUniStream()
	require.ErrorIs(t, err, &StreamLimitReachedError{})
	params := &wire.TransportParameters{
		MaxIdleTimeout:                90 * time.Second,
		InitialMaxStreamDataBidiLocal: 0x5000,
		InitialMaxData:                1337,
		ActiveConnectionIDLimit:       3,
		// marshaling always sets it to this value
		MaxUDPPayloadSize:               protocol.MaxPacketBufferSize,
		OriginalDestinationConnectionID: tc.destConnID,
		MaxBidiStreamNum:                1,
		MaxUniStreamNum:                 1,
	}
	require.NoError(t, tc.conn.handleTransportParameters(params))
	require.Equal(t, protocol.ByteCount(1337), connFC.SendWindowSize())
	_, err = tc.conn.OpenStream()
	require.NoError(t, err)
	_, err = tc.conn.OpenUniStream()
	require.NoError(t, err)

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.ParametersSet{
				Initiator:                     qlog.InitiatorRemote,
				MaxIdleTimeout:                90 * time.Second,
				InitialMaxStreamDataBidiLocal: 0x5000,
				InitialMaxData:                1337,
				ActiveConnectionIDLimit:       3,
				// marshaling always sets it to this value
				MaxUDPPayloadSize:               protocol.MaxPacketBufferSize,
				OriginalDestinationConnectionID: tc.destConnID,
				InitialMaxStreamsBidi:           1,
				InitialMaxStreamsUni:            1,
			},
		},
		eventRecorder.Events(qlog.ParametersSet{}),
	)
}

func TestConnectionTransportParameterValidationFailureServer(t *testing.T) {
	tc := newServerTestConnection(t, nil, nil, false)
	err := tc.conn.handleTransportParameters(&wire.TransportParameters{
		InitialSourceConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
	})
	assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
	assert.ErrorContains(t, err, "expected initial_source_connection_id to equal")
}

func TestConnectionTransportParameterValidationFailureClient(t *testing.T) {
	t.Run("initial_source_connection_id", func(t *testing.T) {
		tc := newClientTestConnection(t, nil, nil, false)
		err := tc.conn.handleTransportParameters(&wire.TransportParameters{
			InitialSourceConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		})
		assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
		assert.ErrorContains(t, err, "expected initial_source_connection_id to equal")
	})

	t.Run("original_destination_connection_id", func(t *testing.T) {
		tc := newClientTestConnection(t, nil, nil, false)
		err := tc.conn.handleTransportParameters(&wire.TransportParameters{
			InitialSourceConnectionID:       tc.destConnID,
			OriginalDestinationConnectionID: protocol.ParseConnectionID([]byte{1, 2, 3, 4}),
		})
		assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
		assert.ErrorContains(t, err, "expected original_destination_connection_id to equal")
	})

	t.Run("retry_source_connection_id if no retry", func(t *testing.T) {
		tc := newClientTestConnection(t, nil, nil, false)
		rcid := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		params := &wire.TransportParameters{
			InitialSourceConnectionID:       tc.destConnID,
			OriginalDestinationConnectionID: tc.destConnID,
			RetrySourceConnectionID:         &rcid,
		}
		err := tc.conn.handleTransportParameters(params)
		assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
		assert.ErrorContains(t, err, "received retry_source_connection_id, although no Retry was performed")
	})

	t.Run("retry_source_connection_id missing", func(t *testing.T) {
		tc := newClientTestConnection(t,
			nil,
			nil,
			false,
			connectionOptRetrySrcConnID(protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})),
		)
		params := &wire.TransportParameters{
			InitialSourceConnectionID:       tc.destConnID,
			OriginalDestinationConnectionID: tc.destConnID,
		}
		err := tc.conn.handleTransportParameters(params)
		assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
		assert.ErrorContains(t, err, "missing retry_source_connection_id")
	})

	t.Run("retry_source_connection_id incorrect", func(t *testing.T) {
		tc := newClientTestConnection(t,
			nil,
			nil,
			false,
			connectionOptRetrySrcConnID(protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})),
		)
		wrongCID := protocol.ParseConnectionID([]byte{1, 2, 3, 4})
		params := &wire.TransportParameters{
			InitialSourceConnectionID:       tc.destConnID,
			OriginalDestinationConnectionID: tc.destConnID,
			RetrySourceConnectionID:         &wrongCID,
		}
		err := tc.conn.handleTransportParameters(params)
		assert.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.TransportParameterError})
		assert.ErrorContains(t, err, "expected retry_source_connection_id to equal")
	})
}

func TestConnectionHandshakeServer(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newServerTestConnection(
		t,
		mockCtrl,
		nil,
		false,
		connectionOptCryptoSetup(cs),
		connectionOptUnpacker(unpacker),
	)

	// the state transition is driven by processing of a CRYPTO frame
	hdr := &wire.ExtendedHeader{
		Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: protocol.Version1},
		PacketNumberLen: protocol.PacketNumberLen2,
	}
	data, err := (&wire.CryptoFrame{Data: []byte("foobar")}).Append(nil, protocol.Version1)
	require.NoError(t, err)

	cs.EXPECT().DiscardInitialKeys().Times(2)
	gomock.InOrder(
		cs.EXPECT().StartHandshake(gomock.Any()),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
			&unpackedPacket{hdr: hdr, encryptionLevel: protocol.EncryptionHandshake, data: data}, nil,
		),
		cs.EXPECT().HandleMessage([]byte("foobar"), protocol.EncryptionHandshake),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventHandshakeComplete}),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		cs.EXPECT().SetHandshakeConfirmed(),
		cs.EXPECT().GetSessionTicket().Return([]byte("session ticket"), nil),
	)
	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack).AnyTimes()

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	p := getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: monotime.Now()})

	select {
	case <-tc.conn.HandshakeComplete():
	case <-tc.conn.Context().Done():
		t.Fatal("connection context done")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	var foundSessionTicket, foundHandshakeDone, foundNewToken bool
	frames, _, _ := tc.conn.framer.Append(nil, nil, protocol.MaxByteCount, monotime.Now(), protocol.Version1)
	for _, frame := range frames {
		switch f := frame.Frame.(type) {
		case *wire.CryptoFrame:
			assert.Equal(t, []byte("session ticket"), f.Data)
			foundSessionTicket = true
		case *wire.HandshakeDoneFrame:
			foundHandshakeDone = true
		case *wire.NewTokenFrame:
			assert.NotEmpty(t, f.Token)
			foundNewToken = true
		}
	}
	assert.True(t, foundSessionTicket)
	assert.True(t, foundHandshakeDone)
	assert.True(t, foundNewToken)

	// test teardown
	cs.EXPECT().Close()
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.conn.destroy(nil)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionHandshakeClient(t *testing.T) {
	t.Run("without preferred address", func(t *testing.T) {
		testConnectionHandshakeClient(t, false)
	})
	t.Run("with preferred address", func(t *testing.T) {
		testConnectionHandshakeClient(t, true)
	})
}

func testConnectionHandshakeClient(t *testing.T, usePreferredAddress bool) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptCryptoSetup(cs), connectionOptUnpacker(unpacker))
	tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	// the state transition is driven by processing of a CRYPTO frame
	hdr := &wire.ExtendedHeader{
		Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: protocol.Version1},
		PacketNumberLen: protocol.PacketNumberLen2,
	}
	data, err := (&wire.CryptoFrame{Data: []byte("foobar")}).Append(nil, protocol.Version1)
	require.NoError(t, err)

	tp := &wire.TransportParameters{
		OriginalDestinationConnectionID: tc.destConnID,
		MaxIdleTimeout:                  time.Hour,
	}
	preferredAddressConnID := protocol.ParseConnectionID([]byte{10, 8, 6, 4})
	preferredAddressResetToken := protocol.StatelessResetToken{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	if usePreferredAddress {
		tp.PreferredAddress = &wire.PreferredAddress{
			IPv4:                netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 42),
			IPv6:                netip.AddrPortFrom(netip.AddrFrom16([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}), 13),
			ConnectionID:        preferredAddressConnID,
			StatelessResetToken: preferredAddressResetToken,
		}
	}

	packedFirstPacket := make(chan struct{})
	gomock.InOrder(
		cs.EXPECT().StartHandshake(gomock.Any()),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).DoAndReturn(
			func(b bool, bc protocol.ByteCount, t monotime.Time, v protocol.Version) (*coalescedPacket, error) {
				close(packedFirstPacket)
				return &coalescedPacket{buffer: getPacketBuffer(), longHdrPackets: []*longHeaderPacket{{header: hdr}}}, nil
			},
		),
		// initial keys are dropped when the first handshake packet is sent
		cs.EXPECT().DiscardInitialKeys(),
		// no more data to send
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
			&unpackedPacket{hdr: hdr, encryptionLevel: protocol.EncryptionHandshake, data: data}, nil,
		),
		cs.EXPECT().HandleMessage([]byte("foobar"), protocol.EncryptionHandshake),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventReceivedTransportParameters, TransportParameters: tp}),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventHandshakeComplete}),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
	)
	tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).Return(nil, nil).AnyTimes()

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	select {
	case <-packedFirstPacket:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	p := getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: monotime.Now()})

	select {
	case <-tc.conn.HandshakeComplete():
	case <-tc.conn.Context().Done():
		t.Fatal("connection context done")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	require.True(t, mockCtrl.Satisfied())
	// the handshake isn't confirmed until we receive a HANDSHAKE_DONE frame from the server

	data, err = (&wire.HandshakeDoneFrame{}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	done := make(chan struct{})
	tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).Return(nil, nil).AnyTimes()
	gomock.InOrder(
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
			&unpackedPacket{hdr: hdr, encryptionLevel: protocol.Encryption1RTT, data: data}, nil,
		),
		cs.EXPECT().DiscardInitialKeys(),
		cs.EXPECT().SetHandshakeConfirmed(),
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(buf *packetBuffer, _ protocol.ByteCount, _ monotime.Time, _ protocol.Version) (shortHeaderPacket, error) {
				close(done)
				return shortHeaderPacket{}, errNothingToPack
			},
		),
	)
	tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(shortHeaderPacket{}, errNothingToPack).AnyTimes()
	p = getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: monotime.Now()})

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	if usePreferredAddress {
		tc.connRunner.EXPECT().AddResetToken(preferredAddressResetToken, gomock.Any())
	}
	nextConnID := tc.conn.connIDManager.Get()
	if usePreferredAddress {
		require.Equal(t, preferredAddressConnID, nextConnID)
	}

	// test teardown
	cs.EXPECT().Close()
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	if usePreferredAddress {
		tc.connRunner.EXPECT().RemoveResetToken(preferredAddressResetToken)
	}
	tc.conn.destroy(nil)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnection0RTTTransportParameters(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	cs := mocks.NewMockCryptoSetup(mockCtrl)
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newClientTestConnection(t, mockCtrl, nil, false, connectionOptCryptoSetup(cs), connectionOptUnpacker(unpacker))
	tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()

	// the state transition is driven by processing of a CRYPTO frame
	hdr := &wire.ExtendedHeader{
		Header:          wire.Header{Type: protocol.PacketTypeHandshake, Version: protocol.Version1},
		PacketNumberLen: protocol.PacketNumberLen2,
	}
	data, err := (&wire.CryptoFrame{Data: []byte("foobar")}).Append(nil, protocol.Version1)
	require.NoError(t, err)

	restored := &wire.TransportParameters{
		ActiveConnectionIDLimit:        3,
		InitialMaxData:                 0x5000,
		InitialMaxStreamDataBidiLocal:  0x5000,
		InitialMaxStreamDataBidiRemote: 1000,
		InitialMaxStreamDataUni:        1000,
		MaxBidiStreamNum:               500,
		MaxUniStreamNum:                500,
	}
	new := *restored
	new.MaxBidiStreamNum-- // the server is not allowed to reduce the limit
	new.OriginalDestinationConnectionID = tc.destConnID

	packedFirstPacket := make(chan struct{})
	gomock.InOrder(
		cs.EXPECT().StartHandshake(gomock.Any()),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventRestoredTransportParameters, TransportParameters: restored}),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).DoAndReturn(
			func(b bool, bc protocol.ByteCount, t monotime.Time, v protocol.Version) (*coalescedPacket, error) {
				close(packedFirstPacket)
				return &coalescedPacket{buffer: getPacketBuffer(), longHdrPackets: []*longHeaderPacket{{header: hdr}}}, nil
			},
		),
		// initial keys are dropped when the first handshake packet is sent
		cs.EXPECT().DiscardInitialKeys(),
		// no more data to send
		unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
			&unpackedPacket{hdr: hdr, encryptionLevel: protocol.EncryptionHandshake, data: data}, nil,
		),
		cs.EXPECT().HandleMessage([]byte("foobar"), protocol.EncryptionHandshake),
		cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventReceivedTransportParameters, TransportParameters: &new}),
		cs.EXPECT().ConnectionState().Return(handshake.ConnectionState{Used0RTT: true}),
		// cs.EXPECT().NextEvent().Return(handshake.Event{Kind: handshake.EventNoEvent}),
		cs.EXPECT().Close(),
	)
	tc.packer.EXPECT().PackCoalescedPacket(false, gomock.Any(), gomock.Any(), protocol.Version1).Return(nil, nil).AnyTimes()
	tc.packer.EXPECT().PackConnectionClose(gomock.Any(), gomock.Any(), protocol.Version1).Return(&coalescedPacket{buffer: getPacketBuffer()}, nil)
	tc.connRunner.EXPECT().ReplaceWithClosed(gomock.Any(), gomock.Any(), gomock.Any())

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	select {
	case <-packedFirstPacket:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	p := getLongHeaderPacket(t, tc.remoteAddr, hdr, nil)
	tc.conn.handlePacket(receivedPacket{data: p.data, buffer: p.buffer, rcvTime: monotime.Now()})

	select {
	case err := <-errChan:
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.ProtocolViolation})
		require.ErrorContains(t, err, "server sent reduced limits after accepting 0-RTT data")
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
}

func TestConnectionReceivePrioritization(t *testing.T) {
	t.Run("handshake complete", func(t *testing.T) {
		events := testConnectionReceivePrioritization(t, true, 5)
		require.Equal(t, []string{"unpack", "unpack", "unpack", "unpack", "unpack", "pack"}, events)
	})

	// before handshake completion, we trigger packing of a new packet every time we receive a packet
	t.Run("handshake not complete", func(t *testing.T) {
		events := testConnectionReceivePrioritization(t, false, 5)
		require.Equal(t, []string{
			"unpack", "pack",
			"unpack", "pack",
			"unpack", "pack",
			"unpack", "pack",
			"unpack", "pack",
		}, events)
	})
}

func testConnectionReceivePrioritization(t *testing.T, handshakeComplete bool, numPackets int) []string {
	mockCtrl := gomock.NewController(t)
	unpacker := NewMockUnpacker(mockCtrl)
	opts := []testConnectionOpt{connectionOptUnpacker(unpacker)}
	if handshakeComplete {
		opts = append(opts, connectionOptHandshakeConfirmed())
	}
	tc := newServerTestConnection(t, mockCtrl, nil, false, opts...)

	var events []string
	var counter int
	var testDone bool
	done := make(chan struct{})
	unpacker.EXPECT().UnpackShortHeader(gomock.Any(), gomock.Any()).DoAndReturn(
		func(rcvTime monotime.Time, data []byte) (protocol.PacketNumber, protocol.PacketNumberLen, protocol.KeyPhaseBit, []byte, error) {
			counter++
			if counter == numPackets {
				testDone = true
			}
			events = append(events, "unpack")
			return protocol.PacketNumber(counter), protocol.PacketNumberLen2, protocol.KeyPhaseZero, []byte{0, 1} /* PADDING, PING */, nil
		},
	).Times(numPackets)
	switch handshakeComplete {
	case false:
		tc.packer.EXPECT().PackCoalescedPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(b bool, bc protocol.ByteCount, t monotime.Time, v protocol.Version) (*coalescedPacket, error) {
				events = append(events, "pack")
				if testDone {
					close(done)
				}
				return nil, nil
			},
		).AnyTimes()
	case true:
		tc.packer.EXPECT().AppendPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
			func(b *packetBuffer, bc protocol.ByteCount, t monotime.Time, v protocol.Version) (shortHeaderPacket, error) {
				events = append(events, "pack")
				if testDone {
					close(done)
				}
				return shortHeaderPacket{}, errNothingToPack
			},
		).AnyTimes()
	}

	for i := range numPackets {
		tc.conn.handlePacket(getShortHeaderPacket(t, tc.remoteAddr, tc.srcConnID, protocol.PacketNumber(i), []byte("foobar")))
	}

	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// test teardown
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.conn.destroy(nil)
	select {
	case err := <-errChan:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}
	return events
}

// When the send queue blocks, we need to reset the pacing timer, otherwise the run loop might busy-loop.
// See https://github.com/quic-go/quic-go/pull/4943 for more details.

// Send a GSO batch, until we have no more data to send.

// Send a GSO batch, until a packet smaller than the maximum size is packed

func TestConnectionPTOProbePackets(t *testing.T) {
	t.Run("Initial", func(t *testing.T) {
		testConnectionPTOProbePackets(t, protocol.EncryptionInitial)
	})
	t.Run("Handshake", func(t *testing.T) {
		testConnectionPTOProbePackets(t, protocol.EncryptionHandshake)
	})
	t.Run("1-RTT", func(t *testing.T) {
		testConnectionPTOProbePackets(t, protocol.Encryption1RTT)
	})
}

func testConnectionPTOProbePackets(t *testing.T, encLevel protocol.EncryptionLevel) {

	mockCtrl := gomock.NewController(t)
	sph := mockackhandler.NewMockSentPacketHandler(mockCtrl)
	tc := newServerTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptSentPacketHandler(sph),
	)

	var sendMode ackhandler.SendMode
	switch encLevel {
	case protocol.EncryptionInitial:
		sendMode = ackhandler.SendPTOInitial
	case protocol.EncryptionHandshake:
		sendMode = ackhandler.SendPTOHandshake
	case protocol.Encryption1RTT:
		sendMode = ackhandler.SendPTOAppData
	}

	sph.EXPECT().GetLossDetectionTimeout().AnyTimes()
	sph.EXPECT().TimeUntilSend().AnyTimes()
	sph.EXPECT().SendMode(gomock.Any()).Return(sendMode)
	sph.EXPECT().SendMode(gomock.Any()).Return(ackhandler.SendNone)
	sph.EXPECT().ECNMode(gomock.Any())
	sph.EXPECT().QueueProbePacket(encLevel).Return(false)
	sph.EXPECT().SentPacket(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any())

	tc.packer.EXPECT().PackPTOProbePacket(encLevel, gomock.Any(), true, gomock.Any(), protocol.Version1).DoAndReturn(
		func(protocol.EncryptionLevel, protocol.ByteCount, bool, monotime.Time, protocol.Version) (*coalescedPacket, error) {
			return &coalescedPacket{
				buffer:         getPacketBuffer(),
				shortHdrPacket: &shortHeaderPacket{PacketNumber: 1},
			}, nil
		},
	)
	done := make(chan struct{})
	tc.sendConn.EXPECT().Write(gomock.Any(), gomock.Any(), gomock.Any()).Do(
		func([]byte, uint16, protocol.ECN) error { close(done); return nil },
	)

	errChan := make(chan error, 1)
	go func() { errChan <- tc.conn.run() }()
	tc.conn.scheduleSending()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout")
	}

	// test teardown
	tc.connRunner.EXPECT().Remove(gomock.Any()).AnyTimes()
	tc.conn.destroy(nil)

	select {
	case err := <-errChan:
		require.NoError(t, err)
	default:
		t.Fatal("should have timed out")
	}

}

func getVersionNegotiationPacket(src, dest protocol.ConnectionID, versions []protocol.Version) receivedPacket {
	b := wire.ComposeVersionNegotiation(
		protocol.ArbitraryLenConnectionID(src.Bytes()),
		protocol.ArbitraryLenConnectionID(dest.Bytes()),
		versions,
	)
	return receivedPacket{
		rcvTime: monotime.Now(),
		data:    b,
		buffer:  getPacketBuffer(),
	}
}

func TestConnectionVersionNegotiationInvalidPackets(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	var eventRecorder events.Recorder
	tc := newClientTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(&eventRecorder),
	)

	// offers the current version
	vnp := getVersionNegotiationPacket(
		tc.destConnID,
		tc.srcConnID,
		[]protocol.Version{1234, protocol.Version1},
	)
	wasProcessed, err := tc.conn.handleOnePacket(vnp)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
				Raw:     qlog.RawInfo{Length: int(vnp.Size())},
				Trigger: qlog.PacketDropUnexpectedVersion,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
	require.True(t, mockCtrl.Satisfied())
	eventRecorder.Clear()

	// unparseable, since it's missing 2 bytes
	vnp.data = vnp.data[:len(vnp.data)-2]
	wasProcessed, err = tc.conn.handleOnePacket(vnp)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header:  qlog.PacketHeader{PacketType: qlog.PacketTypeVersionNegotiation},
				Raw:     qlog.RawInfo{Length: int(vnp.Size())},
				Trigger: qlog.PacketDropHeaderParseError,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
}

func getRetryPacket(t *testing.T, src, dest, origDest protocol.ConnectionID, token []byte) receivedPacket {
	hdr := wire.Header{
		Type:             protocol.PacketTypeRetry,
		SrcConnectionID:  src,
		DestConnectionID: dest,
		Token:            token,
		Version:          protocol.Version1,
	}
	b, err := (&wire.ExtendedHeader{Header: hdr}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	tag := handshake.GetRetryIntegrityTag(b, origDest, protocol.Version1)
	b = append(b, tag[:]...)
	return receivedPacket{
		rcvTime: monotime.Now(),
		data:    b,
		buffer:  getPacketBuffer(),
	}
}

func TestConnectionRetryDrops(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	var eventRecorder events.Recorder
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newClientTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(&eventRecorder),
		connectionOptUnpacker(unpacker),
	)

	newConnID := protocol.ParseConnectionID([]byte{0xde, 0xad, 0xbe, 0xef})

	// invalid integrity tag
	retry := getRetryPacket(t, newConnID, tc.srcConnID, tc.destConnID, []byte("foobar"))
	retry.data[len(retry.data)-1]++
	wasProcessed, err := tc.conn.handleOnePacket(retry)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  newConnID,
					DestConnectionID: tc.srcConnID,
					Version:          protocol.Version1,
				},
				Raw:     qlog.RawInfo{Length: int(retry.Size())},
				Trigger: qlog.PacketDropPayloadDecryptError,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
	eventRecorder.Clear()

	// receive a retry that doesn't change the connection ID
	retry = getRetryPacket(t, tc.destConnID, tc.srcConnID, tc.destConnID, []byte("foobar"))
	wasProcessed, err = tc.conn.handleOnePacket(retry)
	require.NoError(t, err)
	require.False(t, wasProcessed)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  tc.destConnID,
					DestConnectionID: tc.srcConnID,
					Version:          protocol.Version1,
				},
				Raw:     qlog.RawInfo{Length: int(retry.Size())},
				Trigger: qlog.PacketDropUnexpectedPacket,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
}

func TestConnectionRetryAfterReceivedPacket(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	var eventRecorder events.Recorder
	unpacker := NewMockUnpacker(mockCtrl)
	tc := newClientTestConnection(t,
		mockCtrl,
		nil,
		false,
		connectionOptTracer(&eventRecorder),
		connectionOptUnpacker(unpacker),
	)

	// receive a regular packet
	regular := getPacketWithPacketType(t, tc.srcConnID, protocol.PacketTypeInitial, 200)
	unpacker.EXPECT().UnpackLongHeader(gomock.Any(), gomock.Any()).Return(
		&unpackedPacket{
			hdr:             &wire.ExtendedHeader{Header: wire.Header{Type: protocol.PacketTypeInitial}},
			encryptionLevel: protocol.EncryptionInitial,
		}, nil,
	)
	wasProcessed, err := tc.conn.handleOnePacket(receivedPacket{
		data:       regular,
		buffer:     getPacketBuffer(),
		rcvTime:    monotime.Now(),
		remoteAddr: tc.remoteAddr,
	})
	require.NoError(t, err)
	require.True(t, wasProcessed)

	require.Len(t, eventRecorder.Events(qlog.PacketReceived{}), 1)
	require.Equal(t,
		[]qlogwriter.Event{
			qlog.VersionInformation{
				ChosenVersion:  protocol.Version1,
				ClientVersions: tc.conn.config.Versions,
			},
		},
		eventRecorder.Events(qlog.VersionInformation{}),
	)
	eventRecorder.Clear()

	// receive a retry
	retry := getRetryPacket(t, tc.destConnID, tc.srcConnID, tc.destConnID, []byte("foobar"))
	wasProcessed, err = tc.conn.handleOnePacket(retry)
	require.NoError(t, err)
	require.False(t, wasProcessed)

	require.Equal(t,
		[]qlogwriter.Event{
			qlog.PacketDropped{
				Header: qlog.PacketHeader{
					PacketType:       qlog.PacketTypeRetry,
					SrcConnectionID:  tc.conn.origDestConnID,
					DestConnectionID: tc.srcConnID,
					Version:          tc.conn.version,
				},
				Raw:     qlog.RawInfo{Length: int(retry.Size())},
				Trigger: qlog.PacketDropUnexpectedPacket,
			},
		},
		eventRecorder.Events(qlog.PacketDropped{}),
	)
	eventRecorder.Clear()
}

// When the connection is closed before sending the first packet,
// we don't send a CONNECTION_CLOSE.
// This can happen if there's something wrong the tls.Config, and
// crypto/tls refuses to start the handshake.

func TestConnectionDatagrams(t *testing.T) {
	t.Run("disabled", func(t *testing.T) {
		testConnectionDatagrams(t, false)
	})
	t.Run("enabled", func(t *testing.T) {
		testConnectionDatagrams(t, true)
	})
}

func testConnectionDatagrams(t *testing.T, enabled bool) {
	tc := newServerTestConnection(t, nil, &Config{EnableDatagrams: enabled}, false)

	data, err := (&wire.DatagramFrame{Data: []byte("foo"), DataLenPresent: true}).Append(nil, protocol.Version1)
	require.NoError(t, err)
	data, err = (&wire.DatagramFrame{Data: []byte("bar")}).Append(data, protocol.Version1)
	require.NoError(t, err)
	_, _, _, err = tc.conn.handleFrames(data, protocol.ConnectionID{}, protocol.Encryption1RTT, nil, monotime.Now())

	if !enabled {
		require.ErrorIs(t, err, &qerr.TransportError{ErrorCode: qerr.FrameEncodingError, FrameType: uint64(wire.FrameTypeDatagramWithLength)})
		return
	}

	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	d, err := tc.conn.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("foo"), d)
	d, err = tc.conn.ReceiveDatagram(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte("bar"), d)
}
