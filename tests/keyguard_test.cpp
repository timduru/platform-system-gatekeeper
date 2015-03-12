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
#include <iostream>

#include <keyguard/soft_keyguard.h>

using ::keyguard::SizedBuffer;
using ::testing::Test;
using ::keyguard::EnrollRequest;
using ::keyguard::EnrollResponse;
using ::keyguard::VerifyRequest;
using ::keyguard::VerifyResponse;
using ::keyguard::SoftKeyguard;
using ::keyguard::AuthToken;
using ::keyguard::secure_id_t;

class TestKeyguardFileIo : public ::keyguard::KeyguardFileIo {
public:
    TestKeyguardFileIo() {
        bytes_.length = 0;
    }

    virtual void Write(const char *filename, const uint8_t *bytes, size_t length) {
        bytes_.buffer.reset(new uint8_t[length]);
        memcpy(bytes_.buffer.get(), bytes, length);
        bytes_.length = length;
    }

    virtual size_t Read(const char *filename, UniquePtr<uint8_t> *bytes) const {
        if (!bytes_.buffer.get() || bytes_.length == 0) {
            bytes->reset();
        } else {
            bytes->reset(new uint8_t[bytes_.length]);
            memcpy(bytes->get(), bytes_.buffer.get(), bytes_.length);
        }

        return bytes_.length;
    }

    SizedBuffer bytes_;
};

static void do_enroll(SoftKeyguard &keyguard, EnrollResponse *response) {
    SizedBuffer password;

    password.buffer.reset(new uint8_t[16]);
    password.length = 16;
    memset(password.buffer.get(), 0, 16);
    EnrollRequest request(0, NULL, &password, NULL);

    keyguard.Enroll(request, response);
}

TEST(KeyguardTest, EnrollSuccess) {
    SoftKeyguard keyguard(new TestKeyguardFileIo());
    EnrollResponse response;
    do_enroll(keyguard, &response);
    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_OK, response.error);
}

TEST(KeyguardTest, EnrollBogusData) {
    SoftKeyguard keyguard(new TestKeyguardFileIo());
    SizedBuffer password;
    EnrollResponse response;

    EnrollRequest request(0, NULL, &password, NULL);

    keyguard.Enroll(request, &response);

    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_INVALID, response.error);
}

TEST(KeyguardTest, VerifySuccess) {
    SoftKeyguard keyguard(new TestKeyguardFileIo());
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
        reinterpret_cast<AuthToken *>(response.auth_token.buffer.get());

    ASSERT_EQ((uint32_t) 0, auth_token->authenticator_id);
    ASSERT_NE(~((uint32_t) 0), auth_token->timestamp);
    ASSERT_NE((uint64_t) 0, auth_token->root_secure_user_id);
    ASSERT_NE((uint64_t) 0, auth_token->auxiliary_secure_user_id);
}

TEST(KeyguardTest, VerifyBadPwFile) {
    TestKeyguardFileIo *fw = new TestKeyguardFileIo();
    SoftKeyguard keyguard(fw);
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
    fw->bytes_.buffer.reset();
    keyguard.Verify(request, &response);
    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_OK, response.error);

    AuthToken *auth_token =
        reinterpret_cast<AuthToken *>(response.auth_token.buffer.get());

    ASSERT_EQ((uint32_t) 0, auth_token->authenticator_id);
    ASSERT_NE(~((uint32_t) 0), auth_token->timestamp);
    ASSERT_EQ((uint64_t) 0, auth_token->root_secure_user_id);
    ASSERT_EQ((uint64_t) 0, auth_token->auxiliary_secure_user_id);
}

TEST(KeyguardTest, TrustedReEnroll) {
    SoftKeyguard keyguard(new TestKeyguardFileIo());
    SizedBuffer provided_password;
    EnrollResponse enroll_response;
    SizedBuffer password_handle;

    // do_enroll enrolls an all 0 password
    provided_password.buffer.reset(new uint8_t[16]);
    provided_password.length = 16;
    memset(provided_password.buffer.get(), 0, 16);
    do_enroll(keyguard, &enroll_response);
    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_OK, enroll_response.error);

    // keep a copy of the handle
    password_handle.buffer.reset(new uint8_t[enroll_response.enrolled_password_handle.length]);
    password_handle.length = enroll_response.enrolled_password_handle.length;
    memcpy(password_handle.buffer.get(), enroll_response.enrolled_password_handle.buffer.get(),
            password_handle.length);

    // verify first password
    VerifyRequest request(0, &enroll_response.enrolled_password_handle,
            &provided_password);
    VerifyResponse response;
    keyguard.Verify(request, &response);
    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_OK, response.error);
    AuthToken *auth_token =
        reinterpret_cast<AuthToken *>(response.auth_token.buffer.get());

    secure_id_t secure_id = auth_token->root_secure_user_id;

    // enroll new password
    provided_password.buffer.reset(new uint8_t[16]);
    provided_password.length = 16;
    memset(provided_password.buffer.get(), 0, 16);
    SizedBuffer password;
    password.buffer.reset(new uint8_t[16]);
    memset(password.buffer.get(), 1, 16);
    password.length = 16;
    EnrollRequest enroll_request(0, &password_handle, &password, &provided_password);
    keyguard.Enroll(enroll_request, &enroll_response);
    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_OK, enroll_response.error);

    // verify new password
    password.buffer.reset(new uint8_t[16]);
    memset(password.buffer.get(), 1, 16);
    password.length = 16;
    VerifyRequest new_request(0, &enroll_response.enrolled_password_handle,
            &password);
    keyguard.Verify(new_request, &response);
    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_OK, response.error);
    ASSERT_EQ(secure_id,
        reinterpret_cast<AuthToken *>(response.auth_token.buffer.get())->root_secure_user_id);
}


TEST(KeyguardTest, UntrustedReEnroll) {
    SoftKeyguard keyguard(new TestKeyguardFileIo());
    SizedBuffer provided_password;
    EnrollResponse enroll_response;

    // do_enroll enrolls an all 0 password
    provided_password.buffer.reset(new uint8_t[16]);
    provided_password.length = 16;
    memset(provided_password.buffer.get(), 0, 16);
    do_enroll(keyguard, &enroll_response);
    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_OK, enroll_response.error);

    // verify first password
    VerifyRequest request(0, &enroll_response.enrolled_password_handle,
            &provided_password);
    VerifyResponse response;
    keyguard.Verify(request, &response);
    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_OK, response.error);
    AuthToken *auth_token =
        reinterpret_cast<AuthToken *>(response.auth_token.buffer.get());

    secure_id_t secure_id = auth_token->root_secure_user_id;

    // enroll new password
    SizedBuffer password;
    password.buffer.reset(new uint8_t[16]);
    memset(password.buffer.get(), 1, 16);
    password.length = 16;
    EnrollRequest enroll_request(0, NULL, &password, NULL);
    keyguard.Enroll(enroll_request, &enroll_response);
    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_OK, enroll_response.error);

    // verify new password
    password.buffer.reset(new uint8_t[16]);
    memset(password.buffer.get(), 1, 16);
    password.length = 16;
    VerifyRequest new_request(0, &enroll_response.enrolled_password_handle,
            &password);
    keyguard.Verify(new_request, &response);
    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_OK, response.error);
    ASSERT_NE(secure_id,
        reinterpret_cast<AuthToken *>(response.auth_token.buffer.get())->root_secure_user_id);
}


TEST(KeyguardTest, VerifyBogusData) {
    SoftKeyguard keyguard(new TestKeyguardFileIo());
    SizedBuffer provided_password;
    SizedBuffer password_handle;
    VerifyResponse response;

    VerifyRequest request(0, &provided_password, &password_handle);

    keyguard.Verify(request, &response);

    ASSERT_EQ(::keyguard::keyguard_error_t::KG_ERROR_INVALID, response.error);
}
