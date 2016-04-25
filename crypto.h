// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <string>

#include <gnutls/abstract.h>
#include <gnutls/gnutls.h>
#include <gnutls/urls.h>
#include <gnutls/x509.h>

#include "crypto_callback.h"

namespace vpn_nacl {

class Crypto {
 public:
  Crypto(CryptoCallback* callback);
  virtual ~Crypto() {}

  // Fetch an X.509 certificate DER from Chrome by URL.
  static int ImportCert(gnutls_x509_crt_t cert,
                        const char* url,
                        unsigned flags);

  // Fetch a private key, and if successful, populate callbacks in |pkey|.
  static int ImportPrivkey(gnutls_privkey_t pkey,
                           const char* url,
                           unsigned flags);

 protected:
  CryptoCallback* callback_;

  static Crypto* instance_;
  static Crypto* instance() { return instance_; }

  static void Abort(const char* fmt, ...);

  // Prepare a GnuTLS URL for use in a JS call.
  static int ParseURL(const char* url,
                      std::string* sha256);

  // Private key callbacks.
  static int PrivkeyInfo(gnutls_privkey_t pkey,
                         unsigned int flags,
                         void* userdata);
  static int PrivkeySign(gnutls_privkey_t pkey,
                         void* userdata,
                         const gnutls_datum_t* raw_data,
                         gnutls_datum_t* signature);
  static void PrivkeyDeinit(gnutls_privkey_t pkey,
                            void* userdata);

};

}  // namespace

#endif /* CRYPTO_H_ */
