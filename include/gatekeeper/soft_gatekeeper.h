/*
 * Copyright 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef SOFT_GATEKEEPER_H_
#define SOFT_GATEKEEPER_H_

extern "C" {
#include <openssl/rand.h>
#include <crypto_scrypt.h>
}

#include <UniquePtr.h>
#include <gatekeeper/gatekeeper.h>
#include <iostream>

namespace gatekeeper {


class SoftGateKeeper : public GateKeeper {
public:
    static const uint32_t SIGNATURE_LENGTH_BYTES = 32;

    // scrypt params
    static const uint64_t N = 16384;
    static const uint32_t r = 8;
    static const uint32_t p = 1;

    static const int MAX_UINT_32_CHARS = 11;

    SoftGateKeeper() {
        key_.reset(new uint8_t[SIGNATURE_LENGTH_BYTES]);
        memset(key_.get(), 0, SIGNATURE_LENGTH_BYTES);
    }

    virtual ~SoftGateKeeper() {
    }

    virtual bool GetAuthTokenKey(const uint8_t **auth_token_key,
            uint32_t *length) const {
        if (auth_token_key == NULL || length == NULL) return false;
        *auth_token_key = const_cast<const uint8_t *>(key_.get());
        *length = SIGNATURE_LENGTH_BYTES;
        return true;
    }

    virtual void GetPasswordKey(const uint8_t **password_key, uint32_t *length) {
        if (password_key == NULL || length == NULL) return;
        *password_key = const_cast<const uint8_t *>(key_.get());
        *length = SIGNATURE_LENGTH_BYTES;
    }

    virtual void ComputePasswordSignature(uint8_t *signature, uint32_t signature_length,
            const uint8_t *, uint32_t, const uint8_t *password,
            uint32_t password_length, salt_t salt) const {
        if (signature == NULL) return;
        crypto_scrypt(password, password_length, reinterpret_cast<uint8_t *>(&salt),
                sizeof(salt), N, r, p, signature, signature_length);
    }

    virtual void GetRandom(void *random, uint32_t requested_length) const {
        if (random == NULL) return;
        RAND_pseudo_bytes((uint8_t *) random, requested_length);
    }

    virtual void ComputeSignature(uint8_t *signature, uint32_t signature_length,
            const uint8_t *, uint32_t, const uint8_t *, const uint32_t) const {
        if (signature == NULL) return;
        memset(signature, 0, signature_length);
    }

    virtual uint64_t GetNanosecondsSinceBoot() const {
        struct timespec time;
        int res = clock_gettime(CLOCK_MONOTONIC_RAW, &time);
        if (res < 0) return 0;
        return time.tv_nsec;
    }
private:
    UniquePtr<uint8_t> key_;
};
}

#endif // SOFT_GATEKEEPER_H_

