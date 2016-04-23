// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vpn_module.h"

#include "vpn_instance.h"

namespace vpn_nacl {

pp::Instance* VpnModule::CreateInstance(PP_Instance instance) {
  // Called every time one of our <embed> tags shows up.
  return new VpnInstance(instance);
}

}  // namespace vpn_nacl

namespace pp {

Module* CreateModule() {
  // Called once when the pexe file is loaded.
  return new vpn_nacl::VpnModule();
}

}  // namespace pp
