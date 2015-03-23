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

#ifndef GATEKEEPER_H_
#define GATEKEEPER_H_

#include <stdint.h>
#include <UniquePtr.h>

#include "gatekeeper_messages.h"

namespace gatekeeper {

typedef uint64_t secure_id_t;
typedef uint64_t salt_t;

/**
 * Data format for an authentication record used to prove
 * successful password verification. Consumed by KeyStore
 * and keymaster to determine CryptoObject availability.
 *
 * All fields are written in network order.
 */
const uint8_t AUTH_TOKEN_VERSION = 0;
struct __attribute__ ((__packed__)) AuthToken {
    uint8_t auth_token_version;
    secure_id_t root_secure_user_id;
    secure_id_t auxiliary_secure_user_id;
    uint32_t authenticator_id;
    uint32_t timestamp;
    uint8_t hmac[32];
};

struct password_handle_t;

/**
 * Base class for gatekeeper implementations. Provides all functionality except
 * the ability to create/access keys and compute signatures. These are left up
 * to the platform-specific implementation.
 */
class GateKeeper {
public:
    GateKeeper() {}
    virtual ~GateKeeper() {}

    void Enroll(const EnrollRequest &request, EnrollResponse *response);
    void Verify(const VerifyRequest &request, VerifyResponse *response);

protected:

    // The following methods are intended to be implemented by concrete subclasses

    /**
     * Retrieves the key used by GateKeeper::MintAuthToken to sign the payload
     * of the AuthToken. This is not cached as is may have changed due to an event such
     * as a password change.
     *
     * Writes the length in bytes of the returned key to length if it is not null.
     *
     * Ownership of the auth_token_key pointer is maintained by the implementor.
     *
     */
    virtual void GetAuthTokenKey(const uint8_t **auth_token_key, size_t *length)
        const = 0;
    /**
     * The key used to sign and verify password data.
     *
     * MUST be different from the AuthTokenKey.
     *
     * GetPasswordKey is not const because unlike AuthTokenKey,
     * this value can be cached.
     *
     * Ownership of the password_key pointer is maintained by the implementor.
     *
     */
    virtual void GetPasswordKey(const uint8_t **password_key, size_t *length) = 0;

    /**
     * Uses platform-specific routines to compute a signature on the provided password.
     *
     * This can be implemented as a simple pass-through to ComputeSignature, but is
     * available in case handling for password signatures is different from general
     * purpose signatures.
     *
     * Writes the signature_length size signature to the 'signature' pointer.
     */
    virtual void ComputePasswordSignature(uint8_t *signature, size_t signature_length,
            const uint8_t *key, size_t key_length, const uint8_t *password,
            size_t password_length, salt_t salt) const = 0;

    /**
     * Retrieves a unique, cryptographically randomly generated buffer for use in password
     * hashing, etc.
     *
     * Assings the random to the random UniquePtr, relinquishing ownership to the caller
     */
    virtual void GetRandom(void *random, size_t requested_size) const = 0;

    /**
     * Uses platform-specific routines to compute a signature on the provided message.
     *
     * Writes the signature_length size signature to the 'signature' pointer.
     */
    virtual void ComputeSignature(uint8_t *signature, size_t signature_length,
            const uint8_t *key, size_t key_length, const uint8_t *message,
            const size_t length) const = 0;

    /**
     * Write the password file to persistent storage.
     */
    virtual void ReadPasswordFile(uint32_t uid, SizedBuffer *password_file) const = 0;

    /**
     * Read the password file from persistent storage.
     */
    virtual void WritePasswordFile(uint32_t uid, const SizedBuffer &password_file) const = 0;

    /**
     * Get the time since boot in nanoseconds.
     *
     * Should return 0 on error.
     */
    virtual uint64_t GetNanosecondsSinceBoot() const = 0;

private:
    /**
     * Generates a signed attestation of an authentication event and assings
     * to auth_token UniquePtr.
     * The format is consistent with that of AuthToken above.
     * Also returns the length in length if it is not null.
     */
    void MintAuthToken(UniquePtr<uint8_t> *auth_token, size_t *length, uint32_t timestamp,
            secure_id_t user_id, secure_id_t authenticator_id);

    /**
     * Verifies that handle matches password HMAC'ed with the password_key
     */
    bool DoVerify(const password_handle_t *expected_handle, const SizedBuffer &password);

    /**
     * Verifies that the provided handle matches byte-by-byte what was previously
     * stored as a result of a call to 'Enroll'
     */
    bool ValidatePasswordFile(uint32_t uid, const SizedBuffer &provided_handle);

    /**
     * Populates password_handle with the data provided and computes HMAC.
     */
    bool CreatePasswordHandle(SizedBuffer *password_handle, salt_t salt,
        secure_id_t secure_id, secure_id_t authenticator_id, const uint8_t *password,
        size_t password_length);
};

}

#endif // GATEKEEPER_H_
