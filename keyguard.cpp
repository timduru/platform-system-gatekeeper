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
#include <sys/time.h>

#include <keyguard/google_keyguard.h>

namespace keyguard {

GoogleKeyguard::~GoogleKeyguard() {
    if (password_key_) {
        memset_s(password_key_.get(), 0, sizeof(password_key_.get()) / sizeof(password_key_[0]));
    }
}

void GoogleKeyguard::Enroll(const EnrollRequest &request, EnrollResponse *response) {
    if (response == NULL) return;

    SizedBuffer enrolled_password;
    const SizedBuffer *provided_password = request.GetProvidedPassword();
    if (provided_password == NULL || !provided_password->buffer) {
        response->SetError(KG_ERROR_INVALID);
        return;
    }
    enrolled_password.buffer = ComputeSignature(password_key_.get(),
            provided_password->buffer.get(), provided_password->length, &enrolled_password.length);
    response->SetEnrolledPasswordHandle(&enrolled_password);
}

void GoogleKeyguard::Verify(const VerifyRequest &request, VerifyResponse *response) {
    if (response == NULL) return;

    const SizedBuffer *enrolled_password = request.GetPasswordHandle();
    const SizedBuffer *provided_password = request.GetProvidedPassword();


    if (provided_password == NULL || !provided_password->buffer
            || enrolled_password == NULL || !enrolled_password->buffer) {
        response->SetError(KG_ERROR_INVALID);
        return;
    }

    SizedBuffer signed_provided_password;
    signed_provided_password.buffer = ComputeSignature(password_key_.get(),
            provided_password->buffer.get(), provided_password->length,
            &signed_provided_password.length);
    if (memcmp_s(enrolled_password->buffer.get(), signed_provided_password.buffer.get(),
                enrolled_password->length) == 0) {
        // Signature matches
        SizedBuffer auth_token;
        auth_token.buffer = MintAuthToken(request.GetUserId(), &auth_token.length);
        response->SetVerificationToken(&auth_token);
    } else {
        response->SetError(KG_ERROR_INVALID);
    }
}

std::unique_ptr<uint8_t> GoogleKeyguard::MintAuthToken(uint32_t user_id, size_t *length) {
    AuthToken *auth_token = new AuthToken;
    SizedBuffer serialized_auth_token;

    struct timeval time;
    gettimeofday(&time, NULL);

    auth_token->auth_token_size = sizeof(AuthToken) -
        sizeof(auth_token->auth_token_tag) - sizeof(auth_token->auth_token_size);
    auth_token->user_id = user_id;
    auth_token->timestamp = static_cast<uint64_t>(time.tv_sec);

    size_t hash_len = (size_t)((uint8_t *)&auth_token->hmac_tag - (uint8_t *)auth_token);
    size_t signature_len;
    std::unique_ptr<uint8_t> signature = ComputeSignature(GetAuthTokenKey().get(),
            reinterpret_cast<uint8_t *>(auth_token), hash_len, &signature_len);

    memcpy(&auth_token->hmac, signature.get(), sizeof(auth_token->hmac));
    if (length != NULL) *length = sizeof(AuthToken);
    std::unique_ptr<uint8_t> result(reinterpret_cast<uint8_t *>(auth_token));
    return result;
}
}
