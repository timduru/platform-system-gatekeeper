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

/**
 * Convenience class for easily switching out a testing implementation
 */
class GateKeeperFileIo {
public:
    virtual ~GateKeeperFileIo() {}
    virtual void Write(const char *filename, const uint8_t *bytes, size_t length) = 0;
    virtual size_t Read(const char *filename, UniquePtr<uint8_t> *bytes) const = 0;
};

class SoftGateKeeper : public GateKeeper {
public:
    static const size_t SIGNATURE_LENGTH_BYTES = 32;

    // scrypt params
    static const uint64_t N = 16384;
    static const uint32_t r = 8;
    static const uint32_t p = 1;

    static const int MAX_UINT_32_CHARS = 11;

    SoftGateKeeper(GateKeeperFileIo *file_io) {
        file_io_ = file_io;
        key_.reset(new uint8_t[SIGNATURE_LENGTH_BYTES]);
        memset(key_.get(), 0, SIGNATURE_LENGTH_BYTES);
    }

    virtual ~SoftGateKeeper() {
        delete file_io_;
    }

    virtual void GetAuthTokenKey(const uint8_t **auth_token_key,
            size_t *length) const {
        if (auth_token_key == NULL || length == NULL) return;
        *auth_token_key = const_cast<const uint8_t *>(key_.get());
        *length = SIGNATURE_LENGTH_BYTES;
    }

    virtual void GetPasswordKey(const uint8_t **password_key, size_t *length) {
        if (password_key == NULL || length == NULL) return;
        *password_key = const_cast<const uint8_t *>(key_.get());
        *length = SIGNATURE_LENGTH_BYTES;
    }

    virtual void ComputePasswordSignature(uint8_t *signature, size_t signature_length,
            const uint8_t *, size_t, const uint8_t *password,
            size_t password_length, salt_t salt) const {
        if (signature == NULL) return;
        crypto_scrypt(password, password_length, reinterpret_cast<uint8_t *>(&salt),
                sizeof(salt), N, r, p, signature, signature_length);
    }

    virtual void GetRandom(void *random, size_t requested_length) const {
        if (random == NULL) return;
        RAND_pseudo_bytes((uint8_t *) random, requested_length);
    }

    virtual void ComputeSignature(uint8_t *signature, size_t signature_length,
            const uint8_t *, size_t, const uint8_t *, const size_t) const {
        if (signature == NULL) return;
        memset(signature, 0, signature_length);
    }

    virtual void ReadPasswordFile(uint32_t uid, SizedBuffer *password_file) const {
        char buf[MAX_UINT_32_CHARS];
        sprintf(buf, "%u", uid);
        UniquePtr<uint8_t> password_buffer;
        size_t length = file_io_->Read(buf, &password_buffer);
        password_file->buffer.reset(password_buffer.release());
        password_file->length = length;
    }

    virtual void WritePasswordFile(uint32_t uid, const SizedBuffer &password_file) const {
        char buf[MAX_UINT_32_CHARS];
        sprintf(buf, "%u", uid);
        file_io_->Write(buf, password_file.buffer.get(), password_file.length);
    }

    virtual uint64_t GetNanosecondsSinceBoot() const {
        struct timespec time;
        int res = clock_gettime(CLOCK_MONOTONIC_RAW, &time);
        if (res < 0) return 0;
        return time.tv_nsec;
    }
private:
    GateKeeperFileIo *file_io_;
    UniquePtr<uint8_t> key_;
};
}

#endif // SOFT_GATEKEEPER_H_

