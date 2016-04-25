// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vpn_instance.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openconnect.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <functional>
#include <queue>

#include "nacl_io/nacl_io.h"
#include "ppapi/c/ppb_console.h"
#include "ppapi/cpp/completion_callback.h"
#include "ppapi/cpp/instance.h"
#include "ppapi/cpp/module.h"
#include "ppapi/cpp/var.h"
#include "ppapi/cpp/var_array.h"
#include "ppapi/cpp/var_array_buffer.h"
#include "ppapi/cpp/var_dictionary.h"

#define NEW_OC_API 1
#define GETNAMEINFO_WORKS 1

namespace {

// keys
const char* const kCmd = "cmd";
const char* const kData = "data";

// js -> nacl
const char* const kConnect = "connect";
const char* const kDisconnect = "disconnect";
const char* const kPause = "pause";
const char* const kResume = "resume";
const char* const kReconnect = "reconnect";
const char* const kCmdDebug = "debug";
const char* const kCryptoGetCert = "crypto-getcert";
const char* const kCryptoGetPrivkey = "crypto-getprivkey";
const char* const kCryptoSign = "crypto-sign";

// nacl -> js
const char* const kStatus = "status";
const char* const kIp = "ip";
const char* const kAuthForm = "auth_form";
const char* const kPeerCert = "peer_cert";
const char* const kAbort = "abort";

// other parameters
const char* const kUrl = "url";

// ip_info fields
const char* const kGatewayIps = "gateway_ips";
const char* const kIpv4Addr = "ipv4_addr";
const char* const kIpv4Netmask = "ipv4_netmask";
const char* const kIpv6Addr = "ipv6_addr";
const char* const kIpv6Netmask = "ipv6_netmask";
const char* const kDns = "dns";
const char* const kNbns = "nbns";
const char* const kDomain = "domain";
const char* const kProxyPac = "proxy_pac";
const char* const kMtu = "mtu";
const char* const kSplitDns = "split_dns";
const char* const kSplitIncludes = "split_includes";
const char* const kSplitExcludes = "split_excludes";

// status values
const char* const kConnected = "connected";
const char* const kReconnected = "reconnected";
const char* const kDisconnected = "disconnected";

// oc_auth_form fields
const char* const kFormBanner = "banner";
const char* const kFormMessage = "message";
const char* const kFormError = "error";
const char* const kFormAuthId = "auth_id";
const char* const kFormMethod = "method";
const char* const kFormAction = "action";
const char* const kFormOpts = "opts";
const char* const kFormAuthgroupSelection = "authgroup_selection";

// oc_form_opt and oc_form_opt_select fields
const char* const kOptType = "type";
const char* const kOptName = "name";
const char* const kOptLabel = "label";
const char* const kOptFlags = "flags";
const char* const kOptChoices = "choices";

// OC_FORM_OPT_* enums
const char* const kOptTypeText = "text";
const char* const kOptTypePassword = "password";
const char* const kOptTypeSelect = "select";
const char* const kOptTypeHidden = "hidden";
const char* const kOptTypeToken = "token";
const char* const kOptTypeUnknown = "unknown";
const char* const kOptFlagIgnore = "ignore";
const char* const kOptFlagNumeric = "numeric";

// oc_choice fields
const char* const kChoiceName = "name";
const char* const kChoiceLabel = "label";
const char* const kChoiceAuthType = "auth_type";
const char* const kChoiceOverrideName = "override_name";
const char* const kChoiceOverrideLabel = "override_label";

// js -> nacl auth_form results
const char* const kResult = "result";
const char* const kSubmit = "submit";
const char* const kCancel = "cancel";
const char* const kNewgroup = "newgroup";

// peer cert validation
const char* const kReason = "reason";
const char* const kHostname = "hostname";
const char* const kCertChain = "cert_chain";
const char* const kCertHash = "cert_hash";
const char* const kAccept = "accept";

// crypto fields
const char* const kHash = "hash";
const char* const kClientCert = "client_cert";
const char* const kSuccess = "success";
const char* const kPrivkeyType = "privkey_type";

// misc constants
const int kReconnectTimeout = 180;
const int kReconnectInterval = 5;

}  // namespace

namespace vpn_nacl {

VpnInstance::VpnInstance(PP_Instance instance) :
    pp::Instance(instance) {
  nacl_io_init_ppapi(instance, pp::Module::Get()->get_browser_interface());
  core_ = pp::Module::Get()->core();
  debug_enabled_ = false;
  InitBackgroundThreads();

  pthread_mutex_init(&lib_mutex_, NULL);

  pthread_cond_init(&auth_result_ready_, NULL);
  pthread_mutex_init(&auth_result_mutex_, NULL);

  pthread_cond_init(&crypto_result_ready_, NULL);
  pthread_mutex_init(&crypto_result_mutex_, NULL);

  crypto_ = new Crypto(this);
}

void VpnInstance::HandleMessage(const pp::Var& var_message) {
  // data from kernel
  if (var_message.is_array_buffer()) {
    pp::VarArrayBuffer* pkt = new pp::VarArrayBuffer(var_message);

    pthread_mutex_lock(&rx_data_mutex_);
    rx_queue_.push(pkt);
    pthread_cond_signal(&rx_data_ready_);
    pthread_mutex_unlock(&rx_data_mutex_);

    return;
  }

  if (!var_message.is_dictionary()) {
    Log(kFatal, "malformed message: not a dictionary");
    return;
  }

  pp::VarDictionary* dict = new pp::VarDictionary(var_message);
  std::string cmd = dict->Get(kCmd).AsString();

  if (cmd == kConnect) {
    SetDesiredState(kStateRunning);
    // dict is passed to ConnectionThread as connect_options_
    Connect(dict);
    return;
  } else if (cmd == kAuthForm || cmd == kPeerCert) {
    // stored in auth_result_
    SendAuthResult(dict);
    return;
  } else if (cmd == kCryptoGetCert || cmd == kCryptoGetPrivkey ||
             cmd == kCryptoSign) {
    // stored in crypto_result_
    SendCryptoResult(dict);
    return;
  } else if (cmd == kDisconnect) {
    SetDesiredState(kStateDisconnected);
    SendCommand(OC_CMD_CANCEL);
  } else if (cmd == kPause) {
    SetDesiredState(kStatePaused);
    SendCommand(OC_CMD_PAUSE);
  } else if (cmd == kResume) {
    SetDesiredState(kStateRunning);
  } else if (cmd == kReconnect) {
    // i.e. drop connection, then immediate reinstate it
    SetDesiredState(kStateRunning);
    SendCommand(OC_CMD_PAUSE);
  } else if (cmd == kCmdDebug) {
    debug_enabled_ = dict->Get(kData).AsBool();
  } else {
    Log(kError, "unrecognized command '%s'", cmd.c_str());
  }

  delete dict;
}

int VpnInstance::CryptoGetCert(std::string& sha256,
                               void** cert_der,
                               size_t* cert_der_len) {
  pp::VarDictionary cmd_dict;

  cmd_dict.Set(kCmd, kCryptoGetCert);
  cmd_dict.Set(kHash, sha256);

  pthread_mutex_lock(&crypto_result_mutex_);
  PostMessage(cmd_dict);
  pthread_cond_wait(&crypto_result_ready_, &crypto_result_mutex_);

  *cert_der = nullptr;
  pp::Var cert_der_var = crypto_result_->Get(kData);
  if (cert_der_var.is_array_buffer()) {
    pp::VarArrayBuffer buf(cert_der_var);
    *cert_der_len = buf.ByteLength();
    *cert_der = malloc(*cert_der_len);
    if (*cert_der) {
      memcpy(*cert_der, buf.Map(), *cert_der_len);
    }
  }

  delete crypto_result_;
  crypto_result_ = nullptr;
  pthread_mutex_unlock(&crypto_result_mutex_);

  return *cert_der ? 0 : -1;
}

int VpnInstance::CryptoGetPrivkey(std::string& sha256,
                                  std::string* pk_algorithm,
                                  std::string* sign_algorithm) {
  pp::VarDictionary cmd_dict;

  cmd_dict.Set(kCmd, kCryptoGetPrivkey);
  cmd_dict.Set(kHash, sha256);

  pthread_mutex_lock(&crypto_result_mutex_);
  PostMessage(cmd_dict);
  pthread_cond_wait(&crypto_result_ready_, &crypto_result_mutex_);

  int ret = -1;
  if (crypto_result_->Get(kSuccess).AsBool()) {
    *pk_algorithm = crypto_result_->Get(kPrivkeyType).AsString();
    ret = 0;
  }

  delete crypto_result_;
  crypto_result_ = nullptr;
  pthread_mutex_unlock(&crypto_result_mutex_);

  return ret;
}

int VpnInstance::CryptoSign(std::string& sha256,
                            void* raw_data,
                            size_t raw_data_len,
                            void** signature,
                            size_t* signature_len) {
  pp::VarDictionary cmd_dict;

  cmd_dict.Set(kCmd, kCryptoSign);
  cmd_dict.Set(kHash, sha256);

  pp::VarArrayBuffer raw_data_var(raw_data_len);
  memcpy(raw_data_var.Map(), raw_data, raw_data_len);
  cmd_dict.Set(kData, raw_data_var);

  pthread_mutex_lock(&crypto_result_mutex_);
  PostMessage(cmd_dict);
  pthread_cond_wait(&crypto_result_ready_, &crypto_result_mutex_);

  *signature = nullptr;
  pp::Var sig_var = crypto_result_->Get(kData);
  if (sig_var.is_array_buffer()) {
    pp::VarArrayBuffer buf(sig_var);
    *signature_len = buf.ByteLength();
    *signature = malloc(*signature_len);
    if (*signature)
      memcpy(*signature, buf.Map(), *signature_len);
  }

  delete crypto_result_;
  crypto_result_ = nullptr;
  pthread_mutex_unlock(&crypto_result_mutex_);

  return *signature ? 0 : -1;
}

void VpnInstance::SendCryptoResult(pp::VarDictionary* dict) {
  pthread_mutex_lock(&crypto_result_mutex_);
  if (crypto_result_) {
    Log(kError, "crypto_result_ is already set");
    delete crypto_result_;
  }
  crypto_result_ = dict;
  pthread_cond_signal(&crypto_result_ready_);
  pthread_mutex_unlock(&crypto_result_mutex_);
}

void VpnInstance::SimpleMessage(const char* const cmd,
                                const char* const data) {
  pp::VarDictionary dict;

  dict.Set(kCmd, cmd);
  if (data)
    dict.Set(kData, data);

  PostMessage(dict);
}

void VpnInstance::VLog(VpnLogLevel level, const char* fmt, va_list ap) {
  PP_LogLevel pp_level;

  switch (level) {
    case kDebug:
      if (!debug_enabled_)
        return;
      // fall through
    case kVerbose:
      pp_level = PP_LOGLEVEL_TIP;
      break;
    case kInfo:
      pp_level = PP_LOGLEVEL_LOG;
      break;
    case kWarning:
      pp_level = PP_LOGLEVEL_WARNING;
      break;
    default:
      pp_level = PP_LOGLEVEL_ERROR;
  }

  char msg[kMaxMsg];
  vsnprintf(msg, sizeof(msg), fmt, ap);
  LogToConsole(pp_level, msg);

  // Asks JS to kill the NaCl process (eventually...)
  if (level == kFatal)
    SimpleMessage(kAbort, nullptr);
}

void VpnInstance::Log(VpnLogLevel level, const char* fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  VLog(level, fmt, ap);
  va_end(ap);
}

void VpnInstance::CryptoAbort(const char* fmt, va_list ap) {
  VLog(kFatal, fmt, ap);
}

void VpnInstance::InitBackgroundThreads() {
  int fd_pair[2];
  if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fd_pair) < 0)
    Log(kFatal, "socketpair() failed: %d", errno);

  tun_fd_ = fd_pair[0];
  tun_lib_fd_ = fd_pair[1];

  pthread_cond_init(&rx_data_ready_, NULL);
  pthread_mutex_init(&rx_data_mutex_, NULL);

  pthread_cond_init(&desired_state_ready_, NULL);
  pthread_mutex_init(&desired_state_mutex_, NULL);

  pthread_create(&rx_thread_, NULL, &RxThread, this);
  pthread_create(&tx_thread_, NULL, &TxThread, this);
}

void* VpnInstance::RxThread() {
  pthread_mutex_lock(&rx_data_mutex_);
  while (1) {
    pthread_cond_wait(&rx_data_ready_, &rx_data_mutex_);
    while (!rx_queue_.empty()) {
      pp::VarArrayBuffer* pkt = rx_queue_.front();
      rx_queue_.pop();
      pthread_mutex_unlock(&rx_data_mutex_);

      void* data = pkt->Map();
      int len = pkt->ByteLength();
      if (write(tun_fd_, data, len) != len)
        rx_dropped_++;
      pkt->Unmap();
      delete pkt;

      pthread_mutex_lock(&rx_data_mutex_);
    }
  }

  return NULL;
}

void* VpnInstance::RxThread(void* data) {
  VpnInstance* self = static_cast<VpnInstance*>(data);
  return self->RxThread();
}

void* VpnInstance::TxThread() {
  int ret;
  char pkt[kMaxPkt];

  while (1) {
    ret = read(tun_fd_, pkt, sizeof(pkt));
    if (ret <= 0)
      break;

    pp::VarArrayBuffer out(ret);
    char* data = static_cast<char*>(out.Map());
    memcpy(data, pkt, ret);
    PostMessage(out);
  }
  return NULL;
}

void* VpnInstance::TxThread(void* data) {
  VpnInstance* self = static_cast<VpnInstance*>(data);
  return self->TxThread();
}

void VpnInstance::SetupTunCb() {
  const struct oc_ip_info* ip_info;

  if (openconnect_get_ip_info(oc_, &ip_info, NULL, NULL) < 0) {
    Log(kFatal, "Error retrieving connection parameters");
    return;
  }
  SendIpInfo(ip_info);

  if (openconnect_setup_tun_fd(oc_, tun_lib_fd_) < 0) {
    Log(kFatal, "Error setting up tunnel");
    return;
  }
}

void VpnInstance::SetupTunCb(void* privdata) {
  VpnInstance* self = static_cast<VpnInstance*>(privdata);
  return self->SetupTunCb();
}

void VpnInstance::ReconnectedCb() {
  SimpleMessage(kStatus, kReconnected);
}

void VpnInstance::ReconnectedCb(void* privdata) {
  VpnInstance* self = static_cast<VpnInstance*>(privdata);
  return self->ReconnectedCb();
}

int VpnInstance::PeerCertCb(const char* reason) {
  pp::VarDictionary cmd_dict;

  cmd_dict.Set(kCmd, kPeerCert);
  cmd_dict.Set(kReason, reason);

  cmd_dict.Set(kHostname, openconnect_get_dnsname(oc_));

  pp::VarArray certs;
  struct oc_cert *chain;
  int ncerts = openconnect_get_peer_cert_chain(oc_, &chain);
  if (ncerts <= 0) {
    Log(kWarning, "error retrieving cert chain");
  } else {
    for (int i = 0; i < ncerts; i++) {
      pp::VarArrayBuffer jscert(chain[i].der_len);
      void* buf = jscert.Map();
      memcpy(buf, chain[i].der_data, chain[i].der_len);
      jscert.Unmap();
      certs.Set(i, jscert);
    }
    openconnect_free_peer_cert_chain(oc_, chain);
  }

  cmd_dict.Set(kCertChain, certs);
  cmd_dict.Set(kCertHash, openconnect_get_peer_cert_hash(oc_));

  pthread_mutex_lock(&auth_result_mutex_);
  PostMessage(cmd_dict);
  pthread_cond_wait(&auth_result_ready_, &auth_result_mutex_);

  std::string result = auth_result_->Get(kResult).AsString();
  int ret = -1;
  if (result == kAccept)
    ret = 0;

  delete auth_result_;
  auth_result_ = nullptr;
  pthread_mutex_unlock(&auth_result_mutex_);

  return ret;
}

int VpnInstance::PeerCertCb(void* privdata, const char* reason) {
  VpnInstance* self = static_cast<VpnInstance*>(privdata);
  return self->PeerCertCb(reason);
}

int VpnInstance::NewConfigCb(const char* buf, int buflen) {
  Log(kInfo, "%s", __FUNCTION__);
  return 0;
}

int VpnInstance::NewConfigCb(void* privdata, const char* buf, int buflen) {
  VpnInstance* self = static_cast<VpnInstance*>(privdata);
  return self->NewConfigCb(buf, buflen);
}

void VpnInstance::TranslateSelectOpt(struct oc_form_opt_select* opt,
                                     pp::VarDictionary& opt_dict) {
  pp::VarArray choices;

  for (int i = 0; i < opt->nr_choices; i++) {
    struct oc_choice* in = opt->choices[i];
    pp::VarDictionary out;

    out.Set(kChoiceName, in->name);
    if (in->label)
      out.Set(kChoiceLabel, in->label);
    if (in->auth_type)
      out.Set(kChoiceAuthType, in->auth_type);
    if (in->override_name)
      out.Set(kChoiceOverrideName, in->override_name);
    if (in->override_label)
      out.Set(kChoiceOverrideLabel, in->override_label);

    choices.Set(i, out);
  }
  opt_dict.Set(kOptChoices, choices);
}

void VpnInstance::TranslateOpt(struct oc_form_opt* opt,
                               pp::VarDictionary& opt_dict) {
  opt_dict.Set(kOptName, opt->name);
  if (opt->label)
    opt_dict.Set(kOptLabel, opt->label);

  pp::VarDictionary opt_flags;
  opt_flags.Set(kOptFlagIgnore, !!(opt->flags & OC_FORM_OPT_IGNORE));
  opt_flags.Set(kOptFlagNumeric, !!(opt->flags & OC_FORM_OPT_NUMERIC));
  opt_dict.Set(kOptFlags, opt_flags);

  switch (opt->type) {
    case OC_FORM_OPT_TEXT:
      opt_dict.Set(kOptType, kOptTypeText);
      break;
    case OC_FORM_OPT_PASSWORD:
      opt_dict.Set(kOptType, kOptTypePassword);
      break;
    case OC_FORM_OPT_SELECT:
      opt_dict.Set(kOptType, kOptTypeSelect);
      TranslateSelectOpt(reinterpret_cast<struct oc_form_opt_select*>(opt),
                         opt_dict);
      break;
    case OC_FORM_OPT_HIDDEN:
      opt_dict.Set(kOptType, kOptTypeHidden);
      break;
    case OC_FORM_OPT_TOKEN:
      opt_dict.Set(kOptType, kOptTypeToken);
      break;
    default:
      opt_dict.Set(kOptType, kOptTypeUnknown);
  }
}

int VpnInstance::TranslateAuthResult(pp::VarDictionary* dict,
                                     struct oc_auth_form* form) {
  pp::VarDictionary opts(dict->Get(kFormOpts));

  if (!opts.is_undefined()) {
    struct oc_form_opt* opt;
    for (opt = form->opts; opt; opt = opt->next) {
      pp::Var value = opts.Get(opt->name);
      if (!value.is_undefined()) {
        std::string str = value.AsString();
        openconnect_set_option_value(opt, strdup(str.c_str()));
      }
    }
  }

  std::string result = dict->Get(kResult).AsString();
  if (result == kSubmit)
    return OC_FORM_RESULT_OK;
  else if (result == kCancel)
    return OC_FORM_RESULT_CANCELLED;
  else if (result == kNewgroup)
    return OC_FORM_RESULT_NEWGROUP;
  else
    return OC_FORM_RESULT_ERR;
}

int VpnInstance::AuthFormCb(struct oc_auth_form* form) {
  pp::VarDictionary cmd_dict;

  cmd_dict.Set(kCmd, kAuthForm);

  // top-level fields
  if (form->banner)
    cmd_dict.Set(kFormBanner, form->banner);
  if (form->message)
    cmd_dict.Set(kFormMessage, form->message);
  if (form->error)
    cmd_dict.Set(kFormError, form->error);
  if (form->auth_id)
    cmd_dict.Set(kFormAuthId, form->auth_id);
  if (form->method)
    cmd_dict.Set(kFormMethod, form->method);
  if (form->action)
    cmd_dict.Set(kFormAction, form->action);

  // individual options
  int id;
  struct oc_form_opt* opt;
  pp::VarArray opt_array;

  for (opt = form->opts, id = 0; opt; opt = opt->next, id++) {
    pp::VarDictionary opt_dict;
    TranslateOpt(opt, opt_dict);
    if (opt == reinterpret_cast<struct oc_form_opt*>(form->authgroup_opt))
      opt_dict.Set(kFormAuthgroupSelection, form->authgroup_selection);
    opt_array.Set(id, opt_dict);
  }

  cmd_dict.Set(kFormOpts, opt_array);

  pthread_mutex_lock(&auth_result_mutex_);
  PostMessage(cmd_dict);
  pthread_cond_wait(&auth_result_ready_, &auth_result_mutex_);

  int ret = TranslateAuthResult(auth_result_, form);

  delete auth_result_;
  auth_result_ = nullptr;
  pthread_mutex_unlock(&auth_result_mutex_);

  return ret;
}

void VpnInstance::SendAuthResult(pp::VarDictionary* dict) {
  pthread_mutex_lock(&auth_result_mutex_);
  if (auth_result_) {
    Log(kError, "auth_result_ is already set");
    delete auth_result_;
  }
  auth_result_ = dict;
  pthread_cond_signal(&auth_result_ready_);
  pthread_mutex_unlock(&auth_result_mutex_);
}

int VpnInstance::AuthFormCb(void* privdata, struct oc_auth_form* form) {
  VpnInstance* self = static_cast<VpnInstance*>(privdata);
  return self->AuthFormCb(form);
}

void VpnInstance::ProgressCb(int level, const char* fmt, va_list ap) {
  VpnLogLevel mapping;

  switch (level) {
    case PRG_TRACE:
      mapping = kDebug;
      break;
    case PRG_DEBUG:
      mapping = kVerbose;
      break;
    case PRG_INFO:
      mapping = kInfo;
      break;
    default:
      mapping = kError;
  }
  VLog(mapping, fmt, ap);
}

void VpnInstance::ProgressCb(void* privdata, int level, const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  VpnInstance* self = static_cast<VpnInstance*>(privdata);
  self->ProgressCb(level, fmt, ap);
  va_end(ap);
}

// TODO: implement getnameinfo() in libnacl_io so we can remove this hack
int VpnInstance::GetAddrInfo(const char* node,
                             const char* service,
                             const struct addrinfo* hints,
                             struct addrinfo** res) {
  int ret = getaddrinfo(node, service, hints, res);
  if (ret)
    return ret;

  struct addrinfo* ai;
  gateway_ips_.clear();
  for (ai = *res; ai; ai = ai->ai_next) {
    char str[INET_ADDRSTRLEN];

    if (ai->ai_family == AF_INET) {
      struct sockaddr_in* s =
          reinterpret_cast<struct sockaddr_in*>(ai->ai_addr);
      inet_ntop(AF_INET, &s->sin_addr, str, sizeof(str));
      gateway_ips_.push_back(str);
    } else if (ai->ai_family == AF_INET6) {
      // TODO: support IPv6
    }
  }

  return 0;
}

int VpnInstance::GetAddrInfo(void* privdata,
                             const char* node,
                             const char* service,
                             const struct addrinfo* hints,
                             struct addrinfo** res) {
  VpnInstance* self = static_cast<VpnInstance*>(privdata);
  return self->GetAddrInfo(node, service, hints, res);
}

void VpnInstance::SendIpInfo(const struct oc_ip_info* ip_info)
{
  pp::VarDictionary dict;

  dict.Set(kCmd, kIp);

  if (ip_info->addr)
    dict.Set(kIpv4Addr, ip_info->addr);
  if (ip_info->netmask)
  dict.Set(kIpv4Netmask, ip_info->netmask);
  if (ip_info->addr6)
    dict.Set(kIpv6Addr, ip_info->addr6);
  if (ip_info->netmask6)
    dict.Set(kIpv6Netmask, ip_info->netmask6);
  if (ip_info->domain)
    dict.Set(kDomain, ip_info->domain);
  if (ip_info->proxy_pac)
    dict.Set(kProxyPac, ip_info->proxy_pac);
  dict.Set(kMtu, ip_info->mtu);

  int i;
  pp::VarArray dns;
  for (i = 0; i < 3; i++) {
    if (ip_info->dns[i])
      dns.Set(i, ip_info->dns[i]);
  }
  dict.Set(kDns, dns);

  pp::VarArray nbns;
  for (i = 0; i < 3; i++) {
    if (ip_info->nbns[i])
      dns.Set(i, ip_info->nbns[i]);
  }
  dict.Set(kNbns, nbns);

  struct oc_split_include* entry;
  pp::VarArray split_dns;
  for (entry = ip_info->split_dns, i = 0; entry; entry = entry->next)
    split_dns.Set(i++, entry->route);
  dict.Set(kSplitDns, split_dns);

  pp::VarArray split_includes;
  for (entry = ip_info->split_includes, i = 0; entry; entry = entry->next)
    split_includes.Set(i++, entry->route);
  dict.Set(kSplitIncludes, split_includes);

  pp::VarArray split_excludes;
  for (entry = ip_info->split_excludes, i = 0; entry; entry = entry->next)
    split_excludes.Set(i++, entry->route);
  dict.Set(kSplitExcludes, split_excludes);

  pp::VarArray gateway_ips;
#if NEW_OC_API && GETNAMEINFO_WORKS
  gateway_ips.Set(0, ip_info->gateway_addr);
#else
  std::vector<std::string>::iterator it;
  for (it = gateway_ips_.begin(), i = 0; it != gateway_ips_.end(); it++)
    gateway_ips.Set(i++, *it);
#endif
  dict.Set(kGatewayIps, gateway_ips);

  PostMessage(dict);
  SimpleMessage(kStatus, kConnected);
}

void VpnInstance::ConnectionThread() {
  Log(kInfo, "starting connection thread...");

  std::string url = connect_options_->Get(kUrl).AsString();
  if (openconnect_parse_url(oc_, url.c_str()) < 0) {
    Log(kFatal, "Can't parse URL '%s'", url.c_str());
    return;
  }

  pp::Var cert_var = connect_options_->Get(kClientCert);
  if (cert_var.is_string()) {
    const char* cert_url = cert_var.AsString().c_str();
    if (openconnect_set_client_cert(oc_, cert_url, cert_url)) {
      Log(kFatal, "Error setting cert URL '%s'", cert_url);
    }
  }

  openconnect_set_system_trust(oc_, 0);
  if (openconnect_obtain_cookie(oc_) < 0) {
    Log(kFatal, "Error logging in to gateway");
    return;
  }
  if (openconnect_make_cstp_connection(oc_) < 0) {
    Log(kFatal, "Error connecting to gateway");
    return;
  }

  if (openconnect_setup_dtls(oc_, 60))
    Log(kWarning, "Could not configure DTLS");

  cmd_fd_ = openconnect_setup_cmd_pipe(oc_);
  if (cmd_fd_ < 0) {
    Log(kFatal, "Error setting up command interface");
    return;
  }
  if (fcntl(cmd_fd_, F_SETFL, O_NONBLOCK) < 0) {
    Log(kFatal, "Error setting nonblocking mode on cmd_fd: %d", errno);
    return;
  }

#if NEW_OC_API
  openconnect_set_setup_tun_handler(oc_, SetupTunCb);
  openconnect_set_reconnected_handler(oc_, ReconnectedCb);
#else
  SetupTunCb();
#endif

  while (1) {
    pthread_mutex_lock(&desired_state_mutex_);
    if (desired_state_ == kStateDisconnected) {
      pthread_mutex_unlock(&desired_state_mutex_);
      break;
    } else if (desired_state_ == kStatePaused) {
      pthread_cond_wait(&desired_state_ready_, &desired_state_mutex_);
      pthread_mutex_unlock(&desired_state_mutex_);
    } else if (desired_state_ == kStateRunning) {
      pthread_mutex_unlock(&desired_state_mutex_);
      if (openconnect_mainloop(oc_, kReconnectTimeout, kReconnectInterval))
        break;
    }
  }

  SimpleMessage(kStatus, kDisconnected);

  pthread_mutex_lock(&lib_mutex_);
  delete connect_options_;
  connect_options_ = nullptr;
  openconnect_vpninfo_free(oc_);
  cmd_fd_ = 0;
  oc_ = nullptr;
  pthread_mutex_unlock(&lib_mutex_);
}

void* VpnInstance::ConnectionThread(void* privdata) {
  VpnInstance* self = static_cast<VpnInstance*>(privdata);
  self->ConnectionThread();
  return NULL;
}

void VpnInstance::Connect(pp::VarDictionary* dict) {
  pthread_mutex_lock(&lib_mutex_);
  if (oc_) {
    Log(kError, "called Connect() with another session in progress");
    pthread_mutex_unlock(&lib_mutex_);
    return;
  }

  openconnect_init_ssl();
  oc_ = openconnect_vpninfo_new("CrOS", PeerCertCb, NewConfigCb,
      AuthFormCb, ProgressCb, this);
  if (!oc_) {
    Log(kFatal, "unable to create library instance");
    return;
  }

  if (!NEW_OC_API || !GETNAMEINFO_WORKS)
    openconnect_override_getaddrinfo(oc_, &GetAddrInfo);

  connect_options_ = dict;
  gateway_ips_.clear();
  rx_dropped_ = 0;

  pthread_create(&connection_thread_, NULL, &ConnectionThread, this);
  pthread_mutex_unlock(&lib_mutex_);
}

void VpnInstance::SendCommand(char cmd) {
  if (!cmd_fd_ || write(cmd_fd_, &cmd, 1) != 1)
    Log(kWarning, "error writing cmd: %d", errno);
}

void VpnInstance::SetDesiredState(MainloopState new_state) {
  pthread_mutex_lock(&desired_state_mutex_);
  desired_state_ = new_state;
  pthread_cond_signal(&desired_state_ready_);
  pthread_mutex_unlock(&desired_state_mutex_);
}

}  // namespace vpn_nacl
