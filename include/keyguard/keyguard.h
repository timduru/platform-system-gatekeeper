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
 */

#ifndef GOOGLE_KEYGUARD_H_
#define GOOGLE_KEYGUARD_H_

#include <memory>
#include <stdint.h>

#include "keyguard_messages.h"

namespace keyguard {

/**
 * Data format for an authentication record used to prove
 * successful password verification. Consumed by KeyStore
 * and keymaster to determine CryptoObject availability.
 */
struct __attribute__ ((__packed__)) AuthToken {
    const uint8_t auth_token_tag = 0x01;
    uint32_t auth_token_size;
    const uint8_t user_id_tag = 0x02;
    uint32_t user_id;
    const uint8_t authenticator_id_tag = 0x03;
    const uint32_t authenticator_id = 0;
    const uint8_t timestamp_tag = 0x04;
    uint64_t timestamp;
    const uint8_t hmac_tag = 0x06;
    uint8_t hmac[16];
};

/**
 * Base class for keyguard implementations. Provides all functionality except
 * the ability to create/access keys and compute signatures. These are left up
 * to the platform-specific implementation.
 */
class GoogleKeyguard {
public:
    GoogleKeyguard() {}
    virtual ~GoogleKeyguard();

    void Enroll(const EnrollRequest &request, EnrollResponse *response);
    void Verify(const VerifyRequest &request, VerifyResponse *response);

protected:
    /**
     * Generates a signed attestation of an authentication event.
     * The format is consistent with that of AuthToken above.
     */
    std::unique_ptr<uint8_t> MintAuthToken(uint32_t user_id, size_t *length);

    // The following methods are intended to be implemented by concrete subclasses

    /**
     * Retrieves the key used by GoogleKeyguard::MintAuthToken to sign the payload
     * of the AuthToken. This is not cached as is may have changed due to an event such
     * as a password change.
     */
    virtual std::unique_ptr<uint8_t[]> GetAuthTokenKey() const = 0;

    /**
     * Uses platform-specific routines to compute a signature on the provided message.
     * Returns a pointer to the signature, as well as the length in signature_length if
     * it is not NULL.
     */
    virtual std::unique_ptr<uint8_t> ComputeSignature(const uint8_t key[],
            const uint8_t *message, const size_t length, size_t *signature_length) const = 0;

    /**
     * The key used to sign and verify password data. This is different from the AuthTokenKey.
     * It can be cached in this member variable as Keyguard is its only consumer. It should at
     * no point leave Keyguard for any reason.
     */
    std::unique_ptr<uint8_t[]> password_key_;
};
}

#endif // GOOGLE_KEYGUARD_H_
