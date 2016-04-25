// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_CALLBACK_H_
#define CRYPTO_CALLBACK_H_

#include <stdarg.h>

namespace vpn_nacl {

class CryptoCallback {
 public:
  virtual int CryptoGetCert(std::string& sha256,
                            void** cert_der,
                            size_t* cert_der_len) = 0;
  virtual int CryptoGetPrivkey(std::string& sha256,
                               std::string* pk_algorithm,
                               std::string* sign_algorithm) = 0;
  virtual int CryptoSign(std::string& sha256,
                         void* raw_data,
                         size_t raw_data_len,
                         void** signature,
                         size_t* signature_len) = 0;
  virtual void CryptoAbort(const char* fmt,
                           va_list ap) = 0;
};

}  // namespace

#endif /* CRYPTO_CALLBACK_H_ */
