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

#include <gtest/gtest.h>

#include <keyguard/google_keyguard.h>

using ::keyguard::SizedBuffer;
using ::testing::Test;
using ::keyguard::EnrollRequest;
using ::keyguard::EnrollResponse;
using ::keyguard::VerifyRequest;
using ::keyguard::VerifyResponse;
using ::keyguard::GoogleKeyguard;
using ::keyguard::AuthToken;

class FakeKeyguard : public GoogleKeyguard {
public:
    FakeKeyguard() {
        password_key_ = std::unique_ptr<uint8_t[]>(new uint8_t[16] {
                2, 34, 23, 43, 52, 25, 234, 22, 65, 24, 90,
                48, 5, 52, 62, 12 });
    }

private:
    std::unique_ptr<uint8_t[]> GetAuthTokenKey() const {
        return std::unique_ptr<uint8_t[]>(new uint8_t[16] {
                2, 34, 23, 43, 52, 25, 234, 22, 65, 24, 90,
                48, 5, 52, 62, 12 });
    }

    std::unique_ptr<uint8_t> ComputeSignature(const uint8_t key[],
            const uint8_t *message, const size_t length, size_t *signature_length) const {
        const size_t signature_size = 16;
        uint8_t *signature = new uint8_t[signature_size];
        memset(signature, 0, signature_size);
        size_t len = length >= signature_size ? signature_size : length;
        memcpy(signature, message, len);
        if (signature_length != NULL) *signature_length = len;
        return std::unique_ptr<uint8_t>(signature);
    }
};

TEST(KeyguardTest, EnrollSuccess) {
    FakeKeyguard keyguard;
    SizedBuffer password;
    EnrollResponse response;

    password.buffer = std::unique_ptr<uint8_t>(new uint8_t[16]);
    password.length = 16;
    memset(password.buffer.get(), 0, 16);
    EnrollRequest request(0, &password);

    keyguard.Enroll(request, &response);

    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_OK, response.GetError());
    ASSERT_EQ((size_t) 16, response.GetEnrolledPasswordHandle()->length);
}

TEST(KeyguardTest, EnrollBogusData) {
    FakeKeyguard keyguard;
    SizedBuffer password;
    EnrollResponse response;

    EnrollRequest request(0, &password);

    keyguard.Enroll(request, &response);

    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_INVALID, response.GetError());
}

TEST(KeyguardTest, VerifySuccess) {
    FakeKeyguard keyguard;
    SizedBuffer provided_password;
    SizedBuffer password_handle;

    provided_password.buffer = std::unique_ptr<uint8_t>(new uint8_t[16]);
    provided_password.length = 16;
    memset(provided_password.buffer.get(), 0, 16);

    password_handle.buffer = std::unique_ptr<uint8_t>(new uint8_t[16]);
    password_handle.length = 16;
    memset(password_handle.buffer.get(), 0, 16);

    VerifyRequest request(0, &password_handle, &provided_password);
    VerifyResponse response;

    keyguard.Verify(request, &response);

    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_OK, response.GetError());

    AuthToken *auth_token =
        reinterpret_cast<AuthToken *>(response.GetVerificationToken()->buffer.get());

    ASSERT_EQ((uint8_t) 1, auth_token->auth_token_tag);
    ASSERT_EQ((uint8_t) 2, auth_token->user_id_tag);
    ASSERT_EQ((uint8_t) 3, auth_token->authenticator_id_tag);
    ASSERT_EQ((uint8_t) 4, auth_token->timestamp_tag);

    ASSERT_EQ((uint32_t)0, auth_token->user_id);
    ASSERT_EQ((uint32_t)0, auth_token->authenticator_id);
}

TEST(KeyguardTest, VerifyBogusData) {
    FakeKeyguard keyguard;
    SizedBuffer provided_password;
    SizedBuffer password_handle;
    VerifyResponse response;

    VerifyRequest request(0, &provided_password, &password_handle);

    keyguard.Verify(request, &response);

    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_INVALID, response.GetError());
}
