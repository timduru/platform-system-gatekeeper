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
#include <time.h>
#include <iostream>
#include <iomanip>
#include <UniquePtr.h>

#include <keyguard/keyguard.h>

namespace keyguard {

Keyguard::~Keyguard() {
    if (password_key_.buffer.get()) {
        memset_s(password_key_.buffer.get(), 0, password_key_.length);
    }
}

void Keyguard::Enroll(const EnrollRequest &request, EnrollResponse *response) {
    if (response == NULL) return;

    SizedBuffer enrolled_password;
    if (!request.provided_password.buffer.get()) {
        response->error = KG_ERROR_INVALID;
        return;
    }

    size_t salt_length;
    UniquePtr<uint8_t> salt;
    GetSalt(&salt, &salt_length);

    size_t signature_length;
    UniquePtr<uint8_t> signature;
    ComputePasswordSignature(password_key_.buffer.get(),
                password_key_.length, request.provided_password.buffer.get(),
                request.provided_password.length, salt.get(), salt_length, &signature,
                &signature_length);

    SerializeHandle(salt.get(), salt_length, signature.get(), signature_length, enrolled_password);
    response->SetEnrolledPasswordHandle(&enrolled_password);
}

void Keyguard::Verify(const VerifyRequest &request, VerifyResponse *response) {
    if (response == NULL) return;

    if (!request.provided_password.buffer.get() || !request.password_handle.buffer.get()) {
        response->error = KG_ERROR_INVALID;
        return;
    }

    size_t salt_length, signature_length;
    uint8_t *salt, *signature;
    keyguard_error_t error = DeserializeHandle(
            &request.password_handle, &salt, &salt_length, &signature, &signature_length);

    if (error != KG_ERROR_OK) {
        response->error = error;
        return;
    }

    size_t provided_password_signature_length;
    UniquePtr<uint8_t> provided_password_signature;
    ComputePasswordSignature(password_key_.buffer.get(),
            password_key_.length, request.provided_password.buffer.get(), request.provided_password.length,
            salt, salt_length, &provided_password_signature, &provided_password_signature_length);

    if (provided_password_signature_length == signature_length &&
            memcmp_s(signature, provided_password_signature.get(), signature_length) == 0) {
        // Signature matches
        SizedBuffer auth_token;
        MintAuthToken(request.user_id, &auth_token.buffer, &auth_token.length);
        response->SetVerificationToken(&auth_token);
    } else {
        response->error = KG_ERROR_INVALID;
    }
}

void Keyguard::MintAuthToken(uint32_t user_id, UniquePtr<uint8_t> *auth_token, size_t *length) {
    if (auth_token == NULL) return;

    AuthToken *token = new AuthToken;
    SizedBuffer serialized_auth_token;

    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC_RAW, &time);

    token->auth_token_size = sizeof(AuthToken) -
        sizeof(token->auth_token_tag) - sizeof(token->auth_token_size);
    token->user_id = user_id;
    token->timestamp = static_cast<uint64_t>(time.tv_sec);

    UniquePtr<uint8_t> auth_token_key;
    size_t key_len;
    GetAuthTokenKey(&auth_token_key, &key_len);

    size_t hash_len = (size_t)((uint8_t *)&token->hmac_tag - (uint8_t *)token);
    size_t signature_len;
    UniquePtr<uint8_t> signature;
    ComputeSignature(auth_token_key.get(), key_len,
            reinterpret_cast<uint8_t *>(token), hash_len, &signature, &signature_len);

    memset(&token->hmac, 0, sizeof(token->hmac));

    memcpy(&token->hmac, signature.get(), signature_len > sizeof(token->hmac)
            ? sizeof(token->hmac) : signature_len);
    if (length != NULL) *length = sizeof(AuthToken);
    auth_token->reset(reinterpret_cast<uint8_t *>(token));
}

void Keyguard::SerializeHandle(const uint8_t *salt, size_t salt_length, const uint8_t *signature,
        size_t signature_length, SizedBuffer &result) {
    const size_t buffer_len = 2 * sizeof(size_t) + salt_length + signature_length;
    result.buffer.reset(new uint8_t[buffer_len]);
    result.length = buffer_len;
    uint8_t *buffer = result.buffer.get();
    memcpy(buffer, &salt_length, sizeof(salt_length));
    buffer += sizeof(salt_length);
    memcpy(buffer, salt, salt_length);
    buffer += salt_length;
    memcpy(buffer, &signature_length, sizeof(signature_length));
    buffer += sizeof(signature_length);
    memcpy(buffer, signature, signature_length);
}

keyguard_error_t Keyguard::DeserializeHandle(const SizedBuffer *handle, uint8_t **salt,
        size_t *salt_length, uint8_t **password, size_t *password_length) {
    if (handle && handle->length > (2 * sizeof(size_t))) {
        int read = 0;
        uint8_t *buffer = handle->buffer.get();
        memcpy(salt_length, buffer, sizeof(*salt_length));
        read += sizeof(*salt_length);
        if (read + *salt_length < handle->length) {
            *salt = buffer + read;
            read += *salt_length;
            if (read + sizeof(*password_length) < handle->length) {
                buffer += read;
                memcpy(password_length, buffer, sizeof(*password_length));
                *password = buffer + sizeof(*password_length);
            } else {
                return KG_ERROR_INVALID;
            }
        } else {
            return KG_ERROR_INVALID;
        }

        return KG_ERROR_OK;
    }
    return KG_ERROR_INVALID;
}

}
