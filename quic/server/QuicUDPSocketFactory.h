/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/io/async/AsyncUDPSocket.h>

namespace quic {

class QuicUDPSocketFactory {
 public:
  virtual ~QuicUDPSocketFactory() {}

  // Make 参数语义取决于具体的使用场景. 
  // fd 可能为 -1 标识着一个无效的 fd.
  virtual std::unique_ptr<folly::AsyncUDPSocket> make(
      folly::EventBase* evb,
      int fd) = 0;
};
} // namespace quic
