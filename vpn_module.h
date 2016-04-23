// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef VPN_MODULE_H_
#define VPN_MODULE_H_

#include "ppapi/cpp/module.h"

namespace vpn_nacl {

class VpnModule : public pp::Module {
 public:
  VpnModule() : pp::Module() {}
  virtual ~VpnModule() {}
  virtual pp::Instance* CreateInstance(PP_Instance instance);
};

}  // namespace vpn_nacl

#endif /* VPN_MODULE_H_ */
