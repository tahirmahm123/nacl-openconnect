// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VPN_INSTANCE_H_
#define VPN_INSTANCE_H_

#include <openconnect.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdlib.h>

#include <functional>
#include <queue>
#include <string>
#include <vector>

#include "ppapi/cpp/core.h"
#include "ppapi/cpp/instance.h"
#include "ppapi/cpp/message_loop.h"
#include "ppapi/cpp/var.h"
#include "ppapi/cpp/var_array_buffer.h"
#include "ppapi/cpp/var_dictionary.h"

namespace vpn_nacl {

const int kMaxPkt = 1536;
const int kMaxMsg = 256;

typedef enum {
  kDebug = 0,
  kVerbose,
  kInfo,
  kWarning,
  kError,
  kFatal,
} VpnLogLevel;

typedef enum {
  kStateRunning,
  kStateDisconnected,
  kStatePaused,
} MainloopState;

class VpnInstance : public pp::Instance {
 public:
  explicit VpnInstance(PP_Instance instance);
  virtual ~VpnInstance() {}
  virtual void HandleMessage(const pp::Var& var_message);

 protected:
  pp::Core* core_;

  pthread_t rx_thread_;
  std::queue<pp::VarArrayBuffer*> rx_queue_;
  pthread_cond_t rx_data_ready_;
  pthread_mutex_t rx_data_mutex_;

  pthread_t tx_thread_;

  MainloopState desired_state_;
  pthread_cond_t desired_state_ready_;
  pthread_mutex_t desired_state_mutex_;

  pthread_mutex_t lib_mutex_;
  struct openconnect_info* oc_;
  int cmd_fd_;
  int tun_fd_;
  int tun_lib_fd_;

  int rx_dropped_;

  void InitBackgroundThreads();
  void* RxThread();
  static void* RxThread(void *data);
  void* TxThread();
  static void* TxThread(void *data);

  bool debug_enabled_;
  void Log(VpnLogLevel level, const char* fmt, ...);
  void VLog(VpnLogLevel level, const char* fmt, va_list ap);

  void SimpleMessage(const char* const cmd, const char* const data);
  void SendCommand(char cmd);
  void SetDesiredState(MainloopState cmd);

  void Connect(pp::VarDictionary* dict);

  pp::VarDictionary* connect_options_;
  pthread_t connection_thread_;
  std::vector<std::string> gateway_ips_;

  void ConnectionThread();
  static void* ConnectionThread(void* privdata);
  void SendIpInfo(const struct oc_ip_info* ip_info);

  pthread_cond_t auth_result_ready_;
  pthread_mutex_t auth_result_mutex_;
  pp::VarDictionary* auth_result_;
  void TranslateSelectOpt(struct oc_form_opt_select* opt,
                          pp::VarDictionary& opt_dict);
  void TranslateOpt(struct oc_form_opt* opt, pp::VarDictionary& opt_dict);
  int TranslateAuthResult(pp::VarDictionary* dict, struct oc_auth_form* form);
  void SendAuthResult(pp::VarDictionary* dict);

  // Library->VpnInstance callbacks

  void SetupTunCb();
  static void SetupTunCb(void* privdata);

  void ReconnectedCb();
  static void ReconnectedCb(void* privdata);

  int PeerCertCb(const char* reason);
  static int PeerCertCb(void* privdata, const char* reason);

  int NewConfigCb(const char* buf, int buflen);
  static int NewConfigCb(void* privdata, const char* buf, int buflen);

  int AuthFormCb(struct oc_auth_form* form);
  static int AuthFormCb(void* privdata, struct oc_auth_form* form);

  void ProgressCb(int level, const char* fmt, va_list ap);
  static void ProgressCb(void* privdata, int level, const char* fmt, ...);

  int GetAddrInfo(const char* node,
                  const char* service,
                  const struct addrinfo* hints,
                  struct addrinfo** res);
  static int GetAddrInfo(void* privdata,
                         const char* node,
                         const char* service,
                         const struct addrinfo* hints,
                         struct addrinfo** res);
};

}  // namespace vpn_nacl

#endif /* VPN_INSTANCE_H_ */
