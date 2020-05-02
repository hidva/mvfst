/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/Random.h>
#include <folly/SocketAddress.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/net/NetOps.h>
#include <quic/api/QuicTransportBase.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/common/BufUtil.h>

namespace quic {

class ClientHandshakeFactory;

/**
 * QuicClientTransport 的内存管理; 我理解, QuicClientTransport 应该总是要以 std::shared_ptr 的形式引用
 * 着. 并且一定要调用 setSelfOwning() 使得 QuicClientTransport 自身也同时引用着自身, 就像 newClient() 的
 * 做法一样. 所以若 QuicClientTransport 对象是某个类的成员, 那么其存在方式如下:
 * 
 * struct X {
 *  std::shared_ptr<QuicClientTransport> cli_ = QuicClientTransport::newClient();
 *  ~X() {
 *      cli_->close();  // 或者其他关闭函数.
 *  }
 * };
 * 
 * 即在 X 对象析构之后, 其内的 QuicClientTransport 对象实际上仍然存在着的, cli_->close() 调用时, 会开始 QUIC
 * 连接结束的交互, 仍存活的 QuicClientTransport 对象会在 evb 的调度下完成平滑结束连接, 之后会再析构并释放自己.
 */
class QuicClientTransport
    : public QuicTransportBase,
      public folly::AsyncUDPSocket::ReadCallback,
      public folly::AsyncUDPSocket::ErrMessageCallback,
      public std::enable_shared_from_this<QuicClientTransport> {
 public:
  QuicClientTransport(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connectionIdSize = kDefaultConnectionIdSize);

  ~QuicClientTransport() override;

  /**
   * Returns an un-connected QuicClientTransport which is self-owning.
   * The transport is cleaned up when the app calls close() or closeNow() on the
   * transport, or on receiving a terminal ConnectionCallback supplied on
   * start().
   * The transport is self owning in this case is to be able to
   * deal with cases where the app wants to dispose of the transport, however
   * the peer is still sending us packets. If we do not keep the transport alive
   * for this period, the kernel will generate unwanted ICMP echo messages.
   */
  template <class TransportType = QuicClientTransport>
  static std::shared_ptr<TransportType> newClient(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> sock,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
      size_t connectionIdSize = 0) {
    auto client = std::make_shared<TransportType>(
        evb, std::move(sock), std::move(handshakeFactory), connectionIdSize);
    client->setSelfOwning();
    return client;
  }

  /**
   * Supply the hostname to use to validate the server. Must be set before
   * start().
   */
  void setHostname(const std::string& hostname);

  /**
   * Supplies a new peer address to use for the connection. This must be called
   * at least once before start().
   * 
   * 在不开启 happyEyeballs 情况下, 该函数多次调用之后只有一次有效.
   */
  void addNewPeerAddress(folly::SocketAddress peerAddress);
  /**
   * Supplies the local address to use for the connection. Calling this is
   * optional. If not called, INADDR_ANY will be used.
   */
  void setLocalAddress(folly::SocketAddress localAddress);
  void addNewSocket(std::unique_ptr<folly::AsyncUDPSocket> socket);
  void setHappyEyeballsEnabled(bool happyEyeballsEnabled);
  virtual void setHappyEyeballsCachedFamily(sa_family_t cachedFamily);

  /**
   * Starts the connection.
   */
  virtual void start(ConnectionCallback* cb);

  /**
   * Returns whether or not TLS is resumed.
   */
  bool isTLSResumed() const;

  // From QuicTransportBase
  void onReadData(
      const folly::SocketAddress& peer,
      NetworkDataSingle&& networkData) override;
  void writeData() override;
  void closeTransport() override;
  void unbindConnection() override;
  bool hasWriteCipher() const override;
  std::shared_ptr<QuicTransportBase> sharedGuard() override;

  // folly::AsyncUDPSocket::ReadCallback
  void onReadClosed() noexcept override {}
  void onReadError(const folly::AsyncSocketException&) noexcept override;

  // folly::AsyncUDPSocket::ErrMessageCallback
  void errMessage(const cmsghdr& cmsg) noexcept override;
  void errMessageError(const folly::AsyncSocketException&) noexcept override {}

  void setSupportedVersions(const std::vector<QuicVersion>& versions) override;

  /**
   * Set socket options for the underlying socket.
   * Options are being set before and after bind, and not at the time of
   * invoking this function.
   */
  void setSocketOptions(const folly::SocketOptionMap& options) noexcept {
    socketOptions_ = options;
  }

  /**
   * Make QuicClient transport self owning.
   */
  void setSelfOwning();

  /**
   * Used to set private transport parameters that are not in the
   * TransportParameterId enum.
   * See kCustomTransportParameterThreshold in QuicConstants.h
   */
  bool setCustomTransportParameter(
      std::unique_ptr<CustomTransportParameter> customParam);

  void setQLogger(std::shared_ptr<QLogger> qLogger) override;

  void onNetworkSwitch(std::unique_ptr<folly::AsyncUDPSocket> newSock) override;

  /**
   * Set callback for various transport stats (such as packet received, dropped
   * etc). Since the callback is invoked very frequently, it is
   * important that the implementation is efficient.
   */
  void setTransportStatsCallback(
      std::shared_ptr<QuicTransportStatsCallback> statsCallback) noexcept;

  class HappyEyeballsConnAttemptDelayTimeout
      : public folly::HHWheelTimer::Callback {
   public:
    explicit HappyEyeballsConnAttemptDelayTimeout(
        QuicClientTransport* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->happyEyeballsConnAttemptDelayTimeoutExpired();
    }

    void callbackCanceled() noexcept override {}

   private:
    QuicClientTransport* transport_;
  };

 protected:
  // From AsyncUDPSocket::ReadCallback
  void getReadBuffer(void** buf, size_t* len) noexcept override;
  void onDataAvailable(
      const folly::SocketAddress& server,
      size_t len,
      bool truncated,
      OnDataAvailableParams params) noexcept override;
  bool shouldOnlyNotify() override;
  void onNotifyDataAvailable(folly::AsyncUDPSocket& sock) noexcept override;
  void recvMsg(
      folly::AsyncUDPSocket& sock,
      uint64_t readBufferSize,
      int numPackets,
      NetworkData& networkData,
      folly::Optional<folly::SocketAddress>& server,
      size_t& totalData);
  void recvMmsg(
      folly::AsyncUDPSocket& sock,
      uint64_t readBufferSize,
      int numPackets,
      NetworkData& networkData,
      folly::Optional<folly::SocketAddress>& server,
      size_t& totalData);

  void processUDPData(
      const folly::SocketAddress& peer,
      NetworkDataSingle&& networkData);

  void processPacketData(
      const folly::SocketAddress& peer,
      TimePoint receiveTimePoint,
      BufQueue& packetQueue);

  void startCryptoHandshake();

  void happyEyeballsConnAttemptDelayTimeoutExpired() noexcept;

  void handleAckFrame(
      const OutstandingPacket& outstandingPacket,
      const QuicWriteFrame& packetFrame,
      const ReadAckFrame&);

  Buf readBuffer_;
  folly::Optional<std::string> hostname_;
  HappyEyeballsConnAttemptDelayTimeout happyEyeballsConnAttemptDelayTimeout_;

 private:
  void setPartialReliabilityTransportParameter();
  void adjustGROBuffers();

  bool replaySafeNotified_{false};
  // Set it QuicClientTransport is in a self owning mode. This will be cleaned
  // up when the caller invokes a terminal call to the transport.
  std::shared_ptr<QuicClientTransport> selfOwning_;
  bool happyEyeballsEnabled_{false};
  sa_family_t happyEyeballsCachedFamily_{AF_UNSPEC};
  QuicClientConnectionState* clientConn_;
  std::vector<TransportParameter> customTransportParameters_;
  folly::SocketOptionMap socketOptions_;
  std::shared_ptr<QuicTransportStatsCallback> statsCallback_;
  // Same value as conn_->transportSettings.numGROBuffers_ if the kernel
  // supports GRO. otherwise kDefaultNumGROBuffers
  uint32_t numGROBuffers_{kDefaultNumGROBuffers};
  RecvmmsgStorage recvmmsgStorage_;
};
} // namespace quic
