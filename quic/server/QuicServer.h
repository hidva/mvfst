/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <condition_variable>
#include <memory>
#include <vector>

#include <folly/ThreadLocal.h>
#include <folly/container/F14Map.h>
#include <folly/io/SocketOptionMap.h>
#include <folly/io/async/ScopedEventBaseThread.h>

#include <quic/QuicConstants.h>
#include <quic/codec/ConnectionIdAlgo.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/server/QuicServerTransportFactory.h>
#include <quic/server/QuicServerWorker.h>
#include <quic/server/QuicUDPSocketFactory.h>
#include <quic/state/QuicTransportStatsCallback.h>

namespace quic {

/**
 * QuicServer, 负责实现 QUIC server 部分. 参考 'QuicServer 类' 了解该类相关背景. 
 * 参见 EchoServer.h 了解该类如何使用. 
 */
class QuicServer : public QuicServerWorker::WorkerCallback,
                   public std::enable_shared_from_this<QuicServer> {
 public:
  using TransportSettingsOverrideFn =
      std::function<folly::Optional<quic::TransportSettings>(
          const quic::TransportSettings&,
          const folly::IPAddress&)>;

  static std::shared_ptr<QuicServer> createQuicServer() {
    return std::shared_ptr<QuicServer>(new QuicServer());
  }

  virtual ~QuicServer();

  // Initialize and start the quic server where the quic server manages
  // the eventbases for workers
  // address 为监听地址.
  // maxWorkers 指定了 QuicServerWorker 的数目, 若为 0, 则取当前 CPU 数目. 
  void start(const folly::SocketAddress& address, size_t maxWorkers);

  // Initialize quic server worker per evb.
  // start(address, workers) 会调用该函数来初始化相应的结构.
  // address, 为监听地址. initialize 应该为 evbs 中每一个 eventbase 初始化对应的 QuicWorkerServer 实例,
  // useDefaultTransport, 一般为 true. 意味着新建 QuicWorkerServer 实例使用当前 QuicServer 
  // transportFactory_ 来作为 transport factory.
  void initialize(
      const folly::SocketAddress& address,
      const std::vector<folly::EventBase*>& evbs,
      bool useDefaultTransport = false);

  /**
   * start reading from sockets
   * 此时 QuicServerWorker 都已经完成了相关的初始化工作. 已经准备就绪.
   */
  void start();

  /*
   * Pause reading from the listening socket the server workers are bound to
   */
  void pauseRead();

  /*
   * Take in a function to supply overrides for transport parameters, given
   * the client address as input. This can be useful if we are running
   * experiments.
   */
  void setTransportSettingsOverrideFn(TransportSettingsOverrideFn fn);

  /*
   * Transport factory to create server-transport.
   * QuicServer calls 'make()' on the supplied transport factory for *each* new
   * connection.
   * This is useful to do proper set-up on the callers side for each new
   * established connection, such as transport settings and setup sessions.
   */
  void setQuicServerTransportFactory(
      std::unique_ptr<QuicServerTransportFactory> factory);

  /*
   * The socket factory used to create sockets for client connections.  These
   * will end up backing QuicServerTransports and managing per connection state.
   */
  void setQuicUDPSocketFactory(std::unique_ptr<QuicUDPSocketFactory> factory);

  /*
   * The socket factory used to create acceptor sockets.  The sockets created
   * from this factory will listen for udp packets and create new connections
   * via the factory specified in setQuicUDPSocketFactory.
   */
  void setListenerSocketFactory(std::unique_ptr<QuicUDPSocketFactory> factory);

  /**
   * Set factory to create specific congestion controller instances
   * for a given connection
   * This must be set before the server is started.
   */
  void setCongestionControllerFactory(
      std::shared_ptr<CongestionControllerFactory> ccFactory);

  /**
   * Set list of supported QUICVersion for this server. These versions will be
   * used during the 'Version-Negotiation' phase with the client.
   */
  void setSupportedVersion(const std::vector<QuicVersion>& versions);

  /**
   * A token to use for health checking VIPs. When a UDP packet is sent to the
   * server with the exact contents of the health check token, the server will
   * respond with an "OK".
   */
  void setHealthCheckToken(const std::string& healthCheckToken);

  /**
   * Set server TLS context.
   */
  void setFizzContext(
      std::shared_ptr<const fizz::server::FizzServerContext> ctx);

  /**
   * Set server TLS context for a worker associated with the given eventbase.
   */
  void setFizzContext(
      folly::EventBase* evb,
      std::shared_ptr<const fizz::server::FizzServerContext> ctx);

  /**
   * Set socket options for the underlying socket.
   * Options are being set before and after bind, and not at the time of
   * invoking this function.
   */
  void setSocketOptions(const folly::SocketOptionMap& options) noexcept {
    socketOptions_ = options;
  }

  /**
   * Set the server id of the quic server.
   * Note that this function must be called before initialize(..)
   */
  void setProcessId(ProcessId id) noexcept;

  ProcessId getProcessId() const noexcept;

  /**
   * Set the id of the host where this server is running.
   * It is used to make routing decision by setting this id in the ConnectionId
   */
  void setHostId(uint16_t hostId) noexcept;

  /**
   * Get transport settings.
   */
  const TransportSettings& getTransportSettings() const noexcept;

  /**
   * Set initial flow control settings for the connection.
   */
  void setTransportSettings(TransportSettings transportSettings);

  /**
   * Tells the server to start rejecting any new connection
   */
  void rejectNewConnections(bool reject);

  /**
   * Tells the server to disable partial reliability in transport settings.
   * Any new connections negotiated after will have partial reliability enabled
   * or disabled accordingly.
   */
  void enablePartialReliability(bool enabled);

  /**
   * Returns listening address of this server
   */
  const folly::SocketAddress& getAddress() const;

  /**
   * Returns true iff the server is fully initialized
   */
  bool isInitialized() const noexcept;

  /**
   * Shutdown the sever (and all the workers)
   */
  void shutdown(LocalErrorCode error = LocalErrorCode::SHUTTING_DOWN);

  /**
   * Returns true if the server has begun the termination process or if it has
   * not been initialized
   */
  bool hasShutdown() const noexcept;

  /**
   * Blocks the calling thread until isInitialized() is true
   */
  void waitUntilInitialized();

  void handleWorkerError(LocalErrorCode error) override;

  /**
   * Routes the given data for the given client to the correct worker that may
   * have the state for the connection associated with the given data and client
   * 
   * 当 QuicServerWorker 收到不归属自己处理的 packet 时会调用该函数来请求将包发到指定位置.
   * QuicServerWorker 根据 packet dest connection id 中的 worker id 信息来判断当前包是否是需要自己处理的.
   * client, routingData, networkData 存放着 packet 相关信息.
   * isForwardedData 语义与 QuicServerWorker::handleNetworkData() 中同名参数语义相同.
   */
  void routeDataToWorker(
      const folly::SocketAddress& client,
      RoutingData&& routingData,
      NetworkData&& networkData,
      bool isForwardedData = false) override;

  /**
   * Set an EventBaseObserver for server and all its workers. This only works
   * after server is already start()-ed, no-op otherwise.
   */
  void setEventBaseObserver(std::shared_ptr<folly::EventBaseObserver> observer);

  /**
   * Set the transport factory for the worker associated with the given
   * eventbase.
   * This is relevant if the QuicServer is initialized with the vector of
   * event-bases supplied by the caller.
   * Typically, this is useful when the server is already running fixed pool of
   * thread ('workers'), and want to run QuicServer within those workers.
   * In such scenario, the supplied factory's make() will be called (lock-free)
   * upon each new connection establishment within each worker.
   */
  void addTransportFactory(
      folly::EventBase*,
      QuicServerTransportFactory* acceptor);

  /**
   * Initialize necessary steps to enable being taken over of this server by
   * another server, such as binding to a local port so that once another
   * process starts to takeover the port this server is listening to, the other
   * server can forward packets belonging to this server
   * Note that this method cannot be called on a worker's thread.
   * Note that this should also be called after initialize(..),
   * calling this before initialize is undefined.
   */
  void allowBeingTakenOver(const folly::SocketAddress& addr);

  folly::SocketAddress overrideTakeoverHandlerAddress(
      const folly::SocketAddress& addr);

  /*
   * Setup and initialize the listening socket of the old server from the given
   * address to forward misrouted packets belonging to that server during
   * the takeover process
   */
  void startPacketForwarding(const folly::SocketAddress& destAddr);

  /*
   * Disable packet forwarding, even if the packet has no connection id
   * associated with it after the 'delayMS' milliseconds
   */
  void stopPacketForwarding(std::chrono::milliseconds delay);

  /**
   * Set takenover socket fds for the quic server from another process.
   * Quic server calls ::dup for each fd and will not bind to the address for
   * all the valid fds (i.e. not -1) in the given vector
   * NOTE: it must be called before calling 'start()'
   */
  void setListeningFDs(const std::vector<int>& fds);

  /*
   * Returns the File Descriptor of the listening socket for this server.
   */
  int getListeningSocketFD() const;

  /*
   * Returns all the File Descriptor of the listening sockets for each
   * worker for this server.
   */
  std::vector<int> getAllListeningSocketFDs() const noexcept;

  /*
   * Once this server is notified that another server has initiated the takeover
   * it opens a new communication channel so that new server can forward
   * misrouted packets to this server.
   * This method returns the File Descriptor of a local port that this server
   * is listening to.
   */
  int getTakeoverHandlerSocketFD() const;

  TakeoverProtocolVersion getTakeoverProtocolVersion() const noexcept;

  /**
   * Factory to create per worker callback for various transport stats (such as
   * packet received, dropped etc). QuicServer calls 'make' during the
   * initialization _for each worker_.
   * Also, 'make' is called from the worker's eventbase.
   *
   * NOTE: Since the callback is invoked very frequently and per thread,
   * it is important that the implementation of QuicTransportStatsCallback is
   * efficient.
   * NOTE: Quic does not synchronize across threads before calling
   * callbacks for various stats.
   */
  void setTransportStatsCallbackFactory(
      std::unique_ptr<QuicTransportStatsCallbackFactory> statsFactory);

  /**
   * Factory to create per worker ConnectionIdAlgo instance
   * NOTE: it must be set before calling 'start()' or 'initialize(..)'
   */
  void setConnectionIdAlgoFactory(
      std::unique_ptr<ConnectionIdAlgoFactory> connIdAlgoFactory);

  /**
   * Returns vector of running eventbases.
   * This is useful if QuicServer is initialized with a 'default' mode by just
   * specifying number of workers.
   */
  std::vector<folly::EventBase*> getWorkerEvbs() const noexcept;

 private:
  QuicServer();

  // helper function to initialize workers
  // 该函数是 initialize() 一部分. 
  // 为 evbs 中每一个 evb 都新建并初始化一个 QuicServerWorker.
  // 并以此来填充 workers_, evbToWorkers_ 字段.
  // useDefaultTransport 一般为 true.
  void initializeWorkers(
      const std::vector<folly::EventBase*>& evbs,
      bool useDefaultTransport);

  std::unique_ptr<QuicServerWorker> newWorkerWithoutSocket();

  // helper method to run the given function in all worker asynchronously
  void runOnAllWorkers(const std::function<void(QuicServerWorker*)>& func);

  // helper method to run the given function in all worker synchronously
  void runOnAllWorkersSync(const std::function<void(QuicServerWorker*)>& func);

  // 进一步初始化每一个 QuicServerWorker. 主要是初始化 QuicServerWorker 中与 socket 有关的字段.
  void bindWorkersToSocket(
      const folly::SocketAddress& address,
      const std::vector<folly::EventBase*>& evbs);

  std::vector<QuicVersion> supportedVersions_{
      {QuicVersion::MVFST, QuicVersion::MVFST_D24, QuicVersion::QUIC_DRAFT}};
  std::atomic<bool> shutdown_{true};
  std::shared_ptr<const fizz::server::FizzServerContext> ctx_;
  TransportSettings transportSettings_;
  std::mutex startMutex_;
  std::atomic<bool> initialized_{false};
  std::atomic<bool> workersInitialized_{false};
  std::condition_variable startCv_;
  std::atomic<bool> takeoverHandlerInitialized_{false};
  // 所有 QuicServerWorker 所在的 eventbase 列表.
  std::vector<std::unique_ptr<folly::ScopedEventBaseThread>> workerEvbs_;
  // 存放着当前 QuicServer 中所有的 QuicServerWorker 实例.
  std::vector<std::unique_ptr<QuicServerWorker>> workers_;
  // Thread local pointer to QuicServerWorker. This is useful to avoid
  // looking up the worker to route to.
  // NOTE: QuicServer still maintains ownership of all the workers and manages
  // their destruction
  // 每一个 QuicServerWorker 在运行时看到的 workerPtr_ 都是自身.
  folly::ThreadLocalPtr<QuicServerWorker> workerPtr_;
  // evbToWorkers_ 以 hash 形式存放着所有 QuicServerWorker 实例. 
  // key 为 QuicServerWorker 所在 eventbase, value 为 QuicServerWorker 实例自身.
  folly::F14FastMap<folly::EventBase*, QuicServerWorker*> evbToWorkers_;
  // 当 QuicServerWorker 收到建链请求时, 会调用 transportFactory_::make(evb, sock, addr) 来创建出对应的实例.
  // 这里 evb 即当前 QuicServerWorker 所在的 event base.
  // sock, 便是 socketFactory_::make 返回的对象.
  // addr, 为客户端的地址.
  std::unique_ptr<QuicServerTransportFactory> transportFactory_;
  folly::F14FastMap<folly::EventBase*, QuicServerTransportFactory*>
      evbToAcceptors_;
  // factory used for workers to create their listening / bound sockets
  // QuicServerWorker 会使用 listenerSocketFactory_::make(evb, -1) 来创建对应的 listen port.
  // 这里 evb 便是 QuicServerWorker 所在的 eventbase.
  std::unique_ptr<QuicUDPSocketFactory> listenerSocketFactory_;
  // factory used by workers to create sockets for connection transports
  // QuicServerWorker 在收到建链请求, 为构造对应的 QuicServerTransport 实例, 会调用 socketFactory_::make(env, listenerFd) 
  // 相应的 udp socket.
  std::unique_ptr<QuicUDPSocketFactory> socketFactory_;
  // factory used to create specific instance of Congestion control algorithm
  std::shared_ptr<CongestionControllerFactory> ccFactory_;

  std::shared_ptr<folly::EventBaseObserver> evbObserver_;
  folly::Optional<std::string> healthCheckToken_;
  // vector of all the listening fds on each quic server worker
  // 参考 bindWorkersToSocket() 中对 listeningFDs_ 的使用.
  // 我理解该字段类似于一个 hook, 用来实现更细化的控制.
  std::vector<int> listeningFDs_;
  ProcessId processId_{ProcessId::ZERO};
  uint16_t hostId_{0};
  bool rejectNewConnections_{false};
  // factory to create per worker QuicTransportStatsCallback
  std::unique_ptr<QuicTransportStatsCallbackFactory> transportStatsFactory_;
  // factory to create per worker ConnectionIdAlgo
  std::unique_ptr<ConnectionIdAlgoFactory> connIdAlgoFactory_;
  // Impl of ConnectionIdAlgo to make routing decisions from ConnectionId
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  // Used to override certain transport parameters, given the client address
  TransportSettingsOverrideFn transportSettingsOverrideFn_;
  // address that the server is bound to
  // 所有 QuicServerWorker 都监听到这个地址. 
  folly::SocketAddress boundAddress_;
  folly::SocketOptionMap socketOptions_;
};

} // namespace quic
