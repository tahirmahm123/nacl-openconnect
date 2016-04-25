// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include "crypto.h"

namespace vpn_nacl {

const char* const kUrlPrefix = "app:";
const size_t kUrlPrefixLen = 4;

const char* const kKeyTypeRSA = "RSASSA-PKCS1-v1_5";

struct chrome_privkey {
  std::string hash;
  gnutls_pk_algorithm_t pk;
  gnutls_sign_algorithm_t sign_algo;
};

Crypto* Crypto::instance_;

static const gnutls_custom_url_st chrome_url = {
  .name = kUrlPrefix,
  .name_size = kUrlPrefixLen,
  .import_key = &Crypto::ImportPrivkey,
  .import_crt = &Crypto::ImportCert,
};

Crypto::Crypto(CryptoCallback* callback) {
  callback_ = callback;
  if (instance_) {
    Abort("Crypto singleton initialized twice");
  }
  instance_ = this;

  gnutls_global_init();
  if (gnutls_register_custom_url(&chrome_url) < 0) {
    Abort("Error registering custom URL");
  }
}

void Crypto::Abort(const char* fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  instance()->callback_->CryptoAbort(fmt, ap);
  va_end(ap);
}

int Crypto::ParseURL(const char* url,
                     std::string* sha256) {
  if (strncmp(url, kUrlPrefix, kUrlPrefixLen) != 0)
    return -1;
  *sha256 = &url[kUrlPrefixLen];
  return 0;
}

int Crypto::ImportCert(gnutls_x509_crt_t cert,
                       const char* url,
                       unsigned flags) {
  std::string hash;
  if (ParseURL(url, &hash))
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

  void* cert_der;
  size_t cert_der_len;
  if (instance()->callback_->CryptoGetCert(hash, &cert_der, &cert_der_len))
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

  gnutls_datum_t cert_datum = { static_cast<unsigned char* >(cert_der),
                                cert_der_len };
  int ret = gnutls_x509_crt_import(cert, &cert_datum, GNUTLS_X509_FMT_DER);
  free(cert_der);

  return ret;
}

int Crypto::ImportPrivkey(gnutls_privkey_t pkey,
                          const char* url,
                          unsigned flags) {
  std::string hash;
  if (ParseURL(url, &hash))
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

  std::string privkey_type;
  std::string sign_algorithm;
  if (instance()->callback_->CryptoGetPrivkey(hash,
                                              &privkey_type,
                                              &sign_algorithm)) {
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;
  }

  if (privkey_type != kKeyTypeRSA)
    return GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE;

  struct chrome_privkey* priv =
      static_cast<struct chrome_privkey*>(calloc(1, sizeof(*priv)));
  if (!priv)
    return GNUTLS_E_MEMORY_ERROR;

  priv->hash = hash;
  priv->pk = GNUTLS_PK_RSA;
  priv->sign_algo = GNUTLS_SIGN_RSA_SHA256;

  int ret = gnutls_privkey_import_ext3(pkey, priv, &PrivkeySign, NULL,
                                       &PrivkeyDeinit, &PrivkeyInfo, 0);
  if (ret < 0) {
    free(priv);
    return ret;
  }

  return 0;
}

int Crypto::PrivkeyInfo(gnutls_privkey_t pkey,
                        unsigned int flags,
                        void* userdata) {
  struct chrome_privkey* priv = static_cast<struct chrome_privkey*>(userdata);

  if (flags & GNUTLS_PRIVKEY_INFO_PK_ALGO)
    return priv->pk;
  if (flags & GNUTLS_PRIVKEY_INFO_SIGN_ALGO)
    return priv->sign_algo;

  return -1;
}

int Crypto::PrivkeySign(gnutls_privkey_t pkey,
                        void* userdata,
                        const gnutls_datum_t* raw_data,
                        gnutls_datum_t* signature) {
  struct chrome_privkey* priv = static_cast<struct chrome_privkey*>(userdata);
  void* signature_buf;
  size_t signature_len;

  if (instance()->callback_->CryptoSign(priv->hash,
                                        raw_data->data, raw_data->size,
                                        &signature_buf, &signature_len) == 0) {
    signature->data = static_cast<unsigned char*>(signature_buf);
    signature->size = signature_len;
    return 0;
  }

  return GNUTLS_E_PK_SIGN_FAILED;
}

void Crypto::PrivkeyDeinit(gnutls_privkey_t pkey,
                           void* userdata) {
  free(userdata);
}

}  // namespace vpn_nacl
