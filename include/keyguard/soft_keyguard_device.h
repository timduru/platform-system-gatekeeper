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

#ifndef SYSTEM_SOFT_KEYGUARD_DEVICE_H_
#define SYSTEM_SOFT_KEYGUARD_DEVICE_H_

#include <keyguard/soft_keyguard.h>
#include <hardware/keyguard.h>
#include <UniquePtr.h>

namespace keyguard {

/**
 * Software based Keyguard implementation
 *
 * IMPORTANT MAINTAINER NOTE: Pointers to instances of this class must be castable to hw_device_t
 * and keyguard. This means it must remain a standard layout class (no virtual functions and
 * no data members which aren't standard layout), and device_ must be the first data member.
 * Assertions in the constructor validate compliance with those constraints.
 */
class SoftKeyguardDevice {
public:
   SoftKeyguardDevice(const hw_module_t *module);

   hw_device_t *hw_device();

private:
    static int close_device(hw_device_t* dev);

   // Wrappers to translate the keyguard HAL API to the Kegyuard Messages API.

    /**
     * Enrolls password_payload, which should be derived from a user selected pin or password,
     * with the authentication factor private key used only for enrolling authentication
     * factor data.
     *
     * Returns: 0 on success or an error code less than 0 on error.
     * On error, enrolled_password_handle will not be allocated.
     */
    static int enroll(const struct keyguard_device *dev, uint32_t uid,
            const uint8_t *password_payload, size_t password_payload_length,
            uint8_t **enrolled_password_handle, size_t *enrolled_password_handle_length);

    /**
     * Verifies provided_password matches enrolled_password_handle.
     *
     * Implementations of this module may retain the result of this call
     * to attest to the recency of authentication.
     *
     * On success, writes the address of a verification token to verification_token,
     * usable to attest password verification to other trusted services. Clients
     * may pass NULL for this value.
     *
     * Returns: 0 on success or an error code less than 0 on error
     * On error, verification token will not be allocated
     */
    static int verify(const struct keyguard_device *dev, uint32_t uid,
            const uint8_t *enrolled_password_handle, size_t enrolled_password_handle_length,
            const uint8_t *provided_password, size_t provided_password_length,
            uint8_t **verification_token, size_t *verification_token_length);

    keyguard_device device_;
    UniquePtr<Keyguard> impl_;
};

} // namespace keyguard

#endif //SYSTEM_SOFT_KEYGUARD_DEVICE_H_
