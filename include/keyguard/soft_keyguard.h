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

#ifndef SOFT_KEYGUARD_H_
#define SOFT_KEYGUARD_H_

extern "C" {
#include <openssl/rand.h>
#include <crypto_scrypt.h>
}

#include <UniquePtr.h>
#include <keyguard/keyguard.h>

namespace keyguard {

class SoftKeyguard : public Keyguard {
public:
    static const size_t SALT_LENGTH = 8;
    static const size_t SIGNATURE_LENGTH = 16;

    // scrypt params
    static const uint64_t N = 16384;
    static const uint32_t r = 8;
    static const uint32_t p = 1;

    SoftKeyguard() {
        password_key_.buffer.reset();
        password_key_.length = 0;
    }

    virtual void GetAuthTokenKey(UniquePtr<uint8_t> *,
            size_t *length) const {
        // No auth token key for SW impl
        if (length != NULL) *length = 0;
    }

    virtual void ComputePasswordSignature(const uint8_t *, size_t,
            const uint8_t *password, size_t password_length, const uint8_t *salt, size_t salt_length,
            UniquePtr<uint8_t> *signature, size_t *signature_length) const {
        if (signature == NULL) return;
        uint8_t *signature_bytes = new uint8_t[SIGNATURE_LENGTH];
        crypto_scrypt(password, password_length, salt, salt_length, N, r, p,
                signature_bytes, SIGNATURE_LENGTH);
        if (signature_length != NULL) *signature_length = SIGNATURE_LENGTH;
        signature->reset(signature_bytes);
    }

    virtual void GetSalt(UniquePtr<uint8_t> *salt, size_t *salt_length) const {
        if (salt == NULL) return;
        uint8_t *salt_bytes = new uint8_t[SALT_LENGTH];
        RAND_pseudo_bytes(salt_bytes, SALT_LENGTH);
        if (salt_length != NULL) *salt_length = SALT_LENGTH;
        salt->reset(salt_bytes);
    }

    virtual void ComputeSignature(const uint8_t *, size_t,
                const uint8_t *, const size_t, UniquePtr<uint8_t> *signature,
                size_t *signature_length) const {
        if (signature == NULL) return;
        if (signature_length != NULL) *signature_length = SIGNATURE_LENGTH;
        uint8_t *result = new uint8_t[16];
        memset(result, 0, 16);
        signature->reset(result);
    }

};
}
#endif // SOFT_KEYGUARD_H_
