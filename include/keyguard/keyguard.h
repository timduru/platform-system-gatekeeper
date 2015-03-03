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

#ifndef KEYGUARD_H_
#define KEYGUARD_H_

#include <memory>
#include <stdint.h>
#include <UniquePtr.h>

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
class Keyguard {
public:
    Keyguard() {}
    virtual ~Keyguard();

    void Enroll(const EnrollRequest &request, EnrollResponse *response);
    void Verify(const VerifyRequest &request, VerifyResponse *response);

protected:

    // The following methods are intended to be implemented by concrete subclasses

    /**
     * Retrieves the key used by Keyguard::MintAuthToken to sign the payload
     * of the AuthToken. This is not cached as is may have changed due to an event such
     * as a password change.
     *
     * Assigns the auth token to the auth_token_key UniquePtr, relinquishing ownership
     * to the caller.
     * Writes the length in bytes of the returned key to length if it is not null.
     *
     */
    virtual void GetAuthTokenKey(UniquePtr<uint8_t> *auth_token_key, size_t *length)
        const = 0;

    /**
     * Uses platform-specific routines to compute a signature on the provided password.
     *
     * This can be implemented as a simple pass-through to ComputeSignature, but is
     * available in case handling for password signatures is different from general
     * purpose signatures.
     *
     * Assigns the signature to the signature UniquePtr, relinquishing ownership
     * to the caller.
     * Writes the length in bytes of the returned key to signature_length if it is not null.
     *
     */
    virtual void ComputePasswordSignature(const uint8_t *key, size_t key_length,
            const uint8_t *password, size_t password_length, const uint8_t *salt,
            size_t salt_length, UniquePtr<uint8_t> *signature, size_t *signature_length) const = 0;

    /**
     * Retrieves a unique, cryptographically randomly generated salt for use in password
     * hashing.
     *
     * Assings the salt to the salt UniquePtr, relinquishing ownership to the caller
     * Writes the length in bytes of the salt to salt_length if it is not null.
     */
    virtual void GetSalt(UniquePtr<uint8_t> *salt, size_t *salt_length) const = 0;

    /**
     * Uses platform-specific routines to compute a signature on the provided message.
     *
     * Assigns the signature to the signature UniquePtr, relinquishing ownership
     * to the caller.
     * Writes the length in bytes of the returned key to signature_length if it is not null.
     */
    virtual void ComputeSignature(const uint8_t *key, size_t key_length,
            const uint8_t *message, const size_t length, UniquePtr<uint8_t> *signature,
            size_t *signature_length) const = 0;

    /**
     * The key used to sign and verify password data. This is different from the AuthTokenKey.
     * It can be cached in this member variable as Keyguard is its only consumer. It should at
     * no point leave Keyguard for any reason.
     */
    SizedBuffer password_key_;

private:
    /**
     * Generates a signed attestation of an authentication event and assings
     * to auth_token UniquePtr.
     * The format is consistent with that of AuthToken above.
     * Also returns the length in length if it is not null.
     */
    void MintAuthToken(uint32_t user_id, UniquePtr<uint8_t> *auth_token, size_t *length);

    // Takes a salt/signature and their lengths and generates a pasword handle written
    // into result.
    void SerializeHandle(const uint8_t *salt, size_t salt_length, const uint8_t *signature,
        size_t signataure_length, SizedBuffer &result);

    // Takes a handle and generates pointers into the salt and password inside the handle and
    // copies out the sizes of those buffers. Makes no allocations.
    keyguard_error_t DeserializeHandle(const SizedBuffer *handle, uint8_t **salt,
        size_t *salt_length, uint8_t **password, size_t *password_length);

};
}

#endif // KEYGUARD_H_
