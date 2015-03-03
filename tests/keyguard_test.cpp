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
#include <UniquePtr.h>

#include <keyguard/soft_keyguard.h>

using ::keyguard::SizedBuffer;
using ::testing::Test;
using ::keyguard::EnrollRequest;
using ::keyguard::EnrollResponse;
using ::keyguard::VerifyRequest;
using ::keyguard::VerifyResponse;
using ::keyguard::SoftKeyguard;
using ::keyguard::AuthToken;

static void do_enroll(SoftKeyguard &keyguard, EnrollResponse *response) {
    SizedBuffer password;

    password.buffer.reset(new uint8_t[16]);
    password.length = 16;
    memset(password.buffer.get(), 0, 16);
    EnrollRequest request(0, &password);

    keyguard.Enroll(request, response);
}

TEST(KeyguardTest, EnrollSuccess) {
    SoftKeyguard keyguard;
    EnrollResponse response;
    do_enroll(keyguard, &response);
    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_OK, response.error);
}

TEST(KeyguardTest, EnrollBogusData) {
    SoftKeyguard keyguard;
    SizedBuffer password;
    EnrollResponse response;

    EnrollRequest request(0, &password);

    keyguard.Enroll(request, &response);

    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_INVALID, response.error);
}

TEST(KeyguardTest, VerifySuccess) {
    SoftKeyguard keyguard;
    SizedBuffer provided_password;
    EnrollResponse enroll_response;

    provided_password.buffer.reset(new uint8_t[16]);
    provided_password.length = 16;
    memset(provided_password.buffer.get(), 0, 16);

    do_enroll(keyguard, &enroll_response);
    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_OK, enroll_response.error);
    VerifyRequest request(0, &enroll_response.enrolled_password_handle,
            &provided_password);
    VerifyResponse response;

    keyguard.Verify(request, &response);

    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_OK, response.error);

    AuthToken *auth_token =
        reinterpret_cast<AuthToken *>(response.verification_token.buffer.get());

    ASSERT_EQ((uint8_t) 1, auth_token->auth_token_tag);
    ASSERT_EQ((uint8_t) 2, auth_token->user_id_tag);
    ASSERT_EQ((uint8_t) 3, auth_token->authenticator_id_tag);
    ASSERT_EQ((uint8_t) 4, auth_token->timestamp_tag);

    ASSERT_EQ((uint32_t)0, auth_token->user_id);
    ASSERT_EQ((uint32_t)0, auth_token->authenticator_id);
}

TEST(KeyguardTest, VerifyBogusData) {
    SoftKeyguard keyguard;
    SizedBuffer provided_password;
    SizedBuffer password_handle;
    VerifyResponse response;

    VerifyRequest request(0, &provided_password, &password_handle);

    keyguard.Verify(request, &response);

    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_INVALID, response.error);
}
