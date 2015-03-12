/*
 * Copyright (C) 2015 The Android Open Source Project
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
#include <hardware/keyguard.h>

using ::testing::Test;

class KeyguardDeviceTest : public virtual Test {
public:
    KeyguardDeviceTest() {}
    virtual ~KeyguardDeviceTest() {}

    virtual void SetUp() {
        keyguard_device_initialize(&device);
    }

    virtual void TearDown() {
        keyguard_close(device);
    }

    static void keyguard_device_initialize(keyguard_device_t **dev) {
        int ret;
        const hw_module_t *mod;
        ret = hw_get_module_by_class(KEYGUARD_HARDWARE_MODULE_ID, NULL, &mod);

        ASSERT_EQ(0, ret);

        ret = keyguard_open(mod, dev);

        ASSERT_EQ(0, ret);
    }

    keyguard_device_t *device;
};

TEST_F(KeyguardDeviceTest, EnrollAndVerify) {
    size_t password_len = 50;
    uint8_t password_payload[password_len];
    uint8_t *password_handle;
    size_t password_handle_length;
    uint8_t *auth_token;
    size_t auth_token_len;
    int ret;

    ret = device->enroll(device, 0, NULL, 0, NULL, 0,  password_payload, password_len,
            &password_handle, &password_handle_length);

    ASSERT_EQ(0, ret);

    ret = device->verify(device, 0, password_handle, password_handle_length,
            password_payload, password_len, &auth_token, &auth_token_len);

    ASSERT_EQ(0, ret);
}

TEST_F(KeyguardDeviceTest, EnrollAndVerifyBadPassword) {
    size_t password_len = 50;
    uint8_t password_payload[password_len];
    uint8_t *password_handle;
    size_t password_handle_length;
    uint8_t *auth_token = NULL;
    size_t auth_token_len;
    int ret;

    ret = device->enroll(device, 0, NULL, 0, NULL, 0,  password_payload, password_len,
             &password_handle, &password_handle_length);

    ASSERT_EQ(0, ret);

    password_payload[0] = 4;

    ret = device->verify(device, 0, password_handle, password_handle_length,
            password_payload, password_len, &auth_token, &auth_token_len);

    ASSERT_NE(0, ret);
    ASSERT_EQ(NULL, auth_token);
}

