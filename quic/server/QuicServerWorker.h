/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/container/F14Map.h>
#include <folly/container/F14Set.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/AsyncUDPSocket.h>

#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/common/BufAccessor.h>
#include <quic/common/Timers.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/server/QuicServerPacketRouter.h>
#include <quic/server/QuicServerTransportFactory.h>
#include <quic/server/QuicUDPSocketFactory.h>
#include <quic/server/state/ServerConnectionIdRejector.h>
#include <quic/state/QuicTransportStatsCallback.h>

namespace quic {

/**
 * QuicServerWorker, 参考 'QuicServer 类' 了解该类相关背景. 
 */ 
class QuicServerWorker : public folly::AsyncUDPSocket::ReadCallback,
                         public QuicServerTransport::RoutingCallback,
                         public ServerConnectionIdRejector {
 public:
  using TransportSettingsOverrideFn =
      std::function<folly::Optional<quic::TransportSettings>(
          const quic::TransportSettings&,
          const folly::IPAddress&)>;

  class WorkerCallback {
   public:
    virtual ~WorkerCallback() = default;
    // Callback for when the worker has errored
    virtual void handleWorkerError(LocalErrorCode error) = 0;

    virtual void routeDataToWorker(
        const folly::SocketAddress& client,
        RoutingData&& routingData,
        NetworkData&& networkData,
        bool isForwardedData) = 0;
  };

  explicit QuicServerWorker(std::shared_ptr<WorkerCallback> callback);

  ~QuicServerWorker() override;

  folly::EventBase* getEventBase() const;

  void setPacingTimer(TimerHighRes::SharedPtr pacingTimer) noexcept;

  /*
   * Take in a function to supply overrides for transport parameters, given
   * the client address as input. This can be useful if we are running
   * experiments.
   */
  void setTransportSettingsOverrideFn(TransportSettingsOverrideFn fn);

  /**
   * Sets the listening socket
   */
  void setSocket(std::unique_ptr<folly::AsyncUDPSocket> socket);

  /**
   * Sets the socket options
   */
  void setSocketOptions(folly::SocketOptionMap* options) {
    socketOptions_ = options;
  }

  /**
   * Binds to the given address
   */
  void bind(const folly::SocketAddress& address);

  /**
   * start reading data from the socket
   */
  void start();

  /*
   * Pause reading from the listening socket this worker is bound to
   */
  void pauseRead();

  /**
   * Returns listening address of this server
   */
  const folly::SocketAddress& getAddress() const;

  /*
   * Returns the File Descriptor of the listening socket
   */
  int getFD();

  /*
   * Apply all the socket options (pre/post bind).
   * Called after takeover.
   */
  void applyAllSocketOptions();

  /**
   * Initialize and bind given listening socket to the given takeover address
   * so that this server can accept and process misrouted packets forwarded
   * by other server
   */
  void allowBeingTakenOver(
      std::unique_ptr<folly::AsyncUDPSocket> socket,
      const folly::SocketAddress& address);

  /**
   * Override listening address for takeover packets
   * Returns const ref to SocketAddress representing the address it is bound to.
   */
  const folly::SocketAddress& overrideTakeoverHandlerAddress(
      std::unique_ptr<folly::AsyncUDPSocket> socket,
      const folly::SocketAddress& address);

  /**
   * Setup address that the taken over quic server is listening to forward
   * misrouted packets belonging to the old server.
   */
  void startPacketForwarding(const folly::SocketAddress& destAddr);

  /**
   * Stop forwarding of packets and clean up any allocated resources
   */
  void stopPacketForwarding();

  /*
   * Returns the File Descriptor of the listening socket that handles the
   * packets routed from another quic server.
   */
  int getTakeoverHandlerSocketFD();

  TakeoverProtocolVersion getTakeoverProtocolVersion() const noexcept;

  /*
   * Sets the id of the server, that is later used in the routing of the packets
   * The id will be used to set a bit in the ConnectionId for routing.
   */
  void setProcessId(enum ProcessId id) noexcept;

  /*
   * Get the id of the server.
   * The id will be used to set a bit in the ConnectionId for routing (which is
   * later used in the routing of the packets)
   */
  ProcessId getProcessId() const noexcept;

  /**
   * Set the id for this worker thread. Server can make routing decision by
   * setting this id in the ConnectionId
   */
  void setWorkerId(uint8_t id) noexcept;

  /**
   * Returns the id for this worker thread.
   */
  uint8_t getWorkerId() const noexcept;

  /**
   * Set the id for the host where this server is running.
   * It is used to make routing decision by setting this id in the ConnectionId
   */
  void setHostId(uint16_t hostId) noexcept;

  void setNewConnectionSocketFactory(QuicUDPSocketFactory* factory);

  void setTransportFactory(QuicServerTransportFactory* factory);

  void setSupportedVersions(const std::vector<QuicVersion>& supportedVersions);

  void setFizzContext(
      std::shared_ptr<const fizz::server::FizzServerContext> ctx);

  void setTransportSettings(TransportSettings transportSettings);

  /**
   * If true, start to reject any new connection during handshake
   */
  void rejectNewConnections(bool rejectNewConnections);

  /**
   * Enable/disable partial reliability on connection settings.
   */
  void enablePartialReliability(bool enabled);

  /**
   * Set a health-check token that can be used to ping if the server is alive
   */
  void setHealthCheckToken(const std::string& healthCheckToken);

  /**
   * Set callback for various transport stats (such as packet received, dropped
   * etc). Since the callback is invoked very frequently and per thread, it is
   * important that the implementation is efficient.
   * NOTE: Quic does not synchronize across threads before calling it.
   */
  void setTransportStatsCallback(
      std::unique_ptr<QuicTransportStatsCallback> statsCallback) noexcept;

  /**
   * Return callback for recording various transport stats info.
   */
  QuicTransportStatsCallback* getTransportStatsCallback() const noexcept;

  /**
   * Set ConnectionIdAlgo implementation to encode and decode ConnectionId with
   * various info, such as routing related info.
   */
  void setConnectionIdAlgo(
      std::unique_ptr<ConnectionIdAlgo> connIdAlgo) noexcept;

  /**
   * Set factory to create specific congestion controller instances
   * for a given connection
   * This must be set before the server starts (and accepts connections)
   */
  void setCongestionControllerFactory(
      std::shared_ptr<CongestionControllerFactory> factory);

  // Read callback
  void getReadBuffer(void** buf, size_t* len) noexcept override;

  void onDataAvailable(
      const folly::SocketAddress& client,
      size_t len,
      bool truncated,
      OnDataAvailableParams params) noexcept override;

  // Routing callback
  /**
   * Called when a connecton id is available for a new connection (i.e flow)
   * The connection-id here is chosen by this server
   */
  void onConnectionIdAvailable(
      QuicServerTransport::Ptr transport,
      ConnectionId id) noexcept override;

  /**
   * Called when a connecton id is bound and ip address should not
   * be used any more for routing.
   */
  void onConnectionIdBound(
      QuicServerTransport::Ptr transport) noexcept override;

  /**
   * source: Source address and source CID
   * connectionId: destination CID (i.e. server chosen connection-id)
   */
  void onConnectionUnbound(
      QuicServerTransport* transport,
      const QuicServerTransport::SourceIdentity& source,
      const std::vector<ConnectionIdData>& connectionIdData) noexcept override;

  // From ServerConnectionIdRejector:
  bool rejectConnectionId(const ConnectionId& candidate) const
      noexcept override;

  void onReadError(const folly::AsyncSocketException& ex) noexcept override;

  void onReadClosed() noexcept override;

  // 当 QuicServerWorker 收到一个归属于自己处理的 QUIC packet 时, 会调用该函数来处理这个 packet.
  // client, routingData, networkData 存放着 packet 相关信息.
  // isForwardedData 语义与 handleNetworkData() 中同名参数语义相同.
  void dispatchPacketData(
      const folly::SocketAddress& client,
      RoutingData&& routingData,
      NetworkData&& networkData,
      bool isForwardedData = false) noexcept;

  using ConnIdToTransportMap = folly::
      F14FastMap<ConnectionId, QuicServerTransport::Ptr, ConnectionIdHash>;

  struct SourceIdentityHash {
    size_t operator()(const QuicServerTransport::SourceIdentity& sid) const {
      return folly::hash::hash_combine(
          folly::hash::fnv32_buf(sid.second.data(), sid.second.size()),
          sid.first.hash());
    }
  };
  using SrcToTransportMap = folly::F14FastMap<
      QuicServerTransport::SourceIdentity,
      QuicServerTransport::Ptr,
      SourceIdentityHash>;

  const ConnIdToTransportMap& getConnectionIdMap() const;

  const SrcToTransportMap& getSrcToTransportMap() const;

  void shutdownAllConnections(LocalErrorCode error);

  // for unit test
  folly::AsyncUDPSocket::ReadCallback* getTakeoverHandlerCallback() {
    return takeoverCB_.get();
  }

  // public so that it can be called by tests as well.
  // 当 QuicServerWorker 收到一个 QUIC packet 时调用该函数.
  // client 会 quic packet 发送方地址.
  // receiveTime 为收到包时对应的时间.
  // isForwardedData, 若为 true, 则表明当前 packet 被转发过来的, 与 packetForwardingEnabled_ 特性有关.
  // 可以认为 isForwardedData 总是取值为 false.
  void handleNetworkData(
      const folly::SocketAddress& client,
      Buf data,
      const TimePoint& receiveTime,
      bool isForwardedData = false) noexcept;

  /**
   * Try handling the data as a health check.
   */
  bool tryHandlingAsHealthCheck(
      const folly::SocketAddress& client,
      const folly::IOBuf& data);

  /**
   * Forward data to the right QuicServerWorker or to the takeover socket.
   * networkData, routingData, client 存放着待转发 packet 相关信息.
   * isForwardedData, 与 handleNetworkData() 中同名参数语义相同.
   */
  void forwardNetworkData(
      const folly::SocketAddress& client,
      RoutingData&& routingData,
      NetworkData&& networkData,
      bool isForwardedData = false);

  /**
   * Return Infocallback ptr for various transport stats (such as packet
   * received, dropped etc). Since the callback is invoked very frequently and
   * per thread, it is important that the implementation is efficient.
   * NOTE: QuicServer does not synchronize across threads before calling it
   */
  QuicTransportStatsCallback* getStatsCallback() {
    return statsCallback_.get();
  }

 private:
  /**
   * Creates accepting socket from this server's listening address.
   * This socket is powered by the same underlying eventbase
   * for this QuicServerWorker
   */
  std::unique_ptr<folly::AsyncUDPSocket> makeSocket(
      folly::EventBase* evb) const;

  /**
   * Creates accepting socket from the listening address denoted by given fd.
   * This socket is powered by the same underlying eventbase
   * for this QuicServerWorker
   */
  std::unique_ptr<folly::AsyncUDPSocket> makeSocket(
      folly::EventBase* evb,
      int fd) const;

  void sendResetPacket(
      const HeaderForm& headerForm,
      const folly::SocketAddress& client,
      const NetworkData& networkData,
      const ConnectionId& connId);

  bool maybeSendVersionNegotiationPacketOrDrop(
      const folly::SocketAddress& client,
      bool isInitial,
      LongHeaderInvariant& invariant);

  /**
   * Helper method to extract and log routing info from the given (dest) connId
   */
  std::string logRoutingInfo(const ConnectionId& connId) const;

  // 当前 QuicServerWorker 的 listen socket.
  std::unique_ptr<folly::AsyncUDPSocket> socket_;
  folly::SocketOptionMap* socketOptions_{nullptr};
  // 指向着当前 QuicServerWorker 所属的 QuicServer.
  std::shared_ptr<WorkerCallback> callback_; 
  // 当前 QuicServerWorker 所在的 eventbase.
  folly::EventBase* evb_{nullptr};

  // factories are owned by quic server
  QuicUDPSocketFactory* socketFactory_;
  QuicServerTransportFactory* transportFactory_;
  std::shared_ptr<CongestionControllerFactory> ccFactory_{nullptr};

  // A server transport's membership is exclusive to only one of these maps.
  // connectionIdMap_ 存放着当前 QuicServerWorker 管理的所有 QuicServerTransport,
  // 此时 key 为 QuicServerTransport connection id.
  ConnIdToTransportMap connectionIdMap_;
  // 这里 key 为 client address 以及 client connection id. 而不单单是 client address.
  // 与 connectionIdMap_ 一样, 以另外一种形式存放着所有 connection id.
  SrcToTransportMap sourceAddressMap_;

  // Contains every unique transport that is mapped in connectionIdMap_.
  folly::F14FastMap<QuicServerTransport*, std::weak_ptr<QuicServerTransport>>
      boundServerTransports_;

  // 其内存放着 AsyncUDPSocket::ReadCallback::getReadBuffer 所用的缓冲区.
  Buf readBuffer_;
  bool shutdown_{false};
  std::vector<QuicVersion> supportedVersions_;
  std::shared_ptr<const fizz::server::FizzServerContext> ctx_;
  TransportSettings transportSettings_;
  // Same value as transportSettings_.numGROBuffers_ if the kernel
  // supports GRO. otherwise 1
  uint32_t numGROBuffers_{kDefaultNumGROBuffers};
  folly::Optional<Buf> healthCheckToken_;
  bool rejectNewConnections_{false};
  uint8_t workerId_{0};
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  uint16_t hostId_{0};
  // QuicServerWorker maintains ownership of the info stats callback
  std::unique_ptr<QuicTransportStatsCallback> statsCallback_;

  // Handle takeover between processes
  std::unique_ptr<TakeoverHandlerCallback> takeoverCB_;
  enum ProcessId processId_ { ProcessId::ZERO };
  TakeoverPacketHandler takeoverPktHandler_;
  bool packetForwardingEnabled_{false};  // 与 takeover 有关,
  using PacketDropReason = QuicTransportStatsCallback::PacketDropReason;
  TimerHighRes::SharedPtr pacingTimer_;

  // Used to override certain transport parameters, given the client address
  TransportSettingsOverrideFn transportSettingsOverrideFn_;

  // Output buffer to be used for continuous memory GSO write
  std::unique_ptr<BufAccessor> bufAccessor_;
};

} // namespace quic
