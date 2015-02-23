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
#ifndef KEYGUARD_MESSAGES_H_
#define KEYGUARD_MESSAGES_H_

#include <memory>
#include <stdint.h>

namespace keyguard {

typedef enum {
    KG_ERROR_OK = 0,
    KG_ERROR_INVALID = 1,
} keyguard_error_t;

typedef struct {
    std::unique_ptr<uint8_t> buffer;
    size_t length;
} SizedBuffer;

class KeyguardMessage {
public:
    KeyguardMessage() : error_(KG_ERROR_OK) {}
    KeyguardMessage(keyguard_error_t error) : error_(error) {}
    virtual ~KeyguardMessage() {}

    size_t GetSerializedSize() const;
    uint8_t *Serialize() const;
    keyguard_error_t Deserialize(const uint8_t *payload, const uint8_t *end);
    keyguard_error_t GetError() const { return error_; }

protected:
    virtual size_t nonErrorSerializedSize() const { return 0; } ;
    virtual void nonErrorSerialize(uint8_t *buffer) const { }
    virtual keyguard_error_t nonErrorDeserialize(const uint8_t *payload, const uint8_t *end) {
        return KG_ERROR_OK;
    }

    keyguard_error_t error_;
};

class VerifyRequest : public KeyguardMessage {
public:
    VerifyRequest(
            SizedBuffer *enrolled_password_handle,
            SizedBuffer *provided_password_payload);
    VerifyRequest();
    ~VerifyRequest();

    const SizedBuffer *GetPasswordHandle() const { return &password_handle_; }
    const SizedBuffer *GetProvidedPassword() const { return &provided_password_; }

protected:
    virtual size_t nonErrorSerializedSize() const;
    virtual void nonErrorSerialize(uint8_t *buffer) const;
    virtual keyguard_error_t nonErrorDeserialize(const uint8_t *payload, const uint8_t *end);

private:
    SizedBuffer password_handle_;
    SizedBuffer provided_password_;
};

class VerifyResponse : public KeyguardMessage {
public:
    VerifyResponse(SizedBuffer *verification_token);
    VerifyResponse();
    ~VerifyResponse();

    const SizedBuffer *GetVerificationToken() const { return &verification_token_; }

protected:
    virtual size_t nonErrorSerializedSize() const;
    virtual void nonErrorSerialize(uint8_t *buffer) const;
    virtual keyguard_error_t nonErrorDeserialize(const uint8_t *payload, const uint8_t *end);

private:
    SizedBuffer verification_token_;
};

class EnrollRequest : public KeyguardMessage {
public:
    EnrollRequest(SizedBuffer *provided_password);
    EnrollRequest();
    ~EnrollRequest();

    const SizedBuffer *GetProvidedPassword() const { return &provided_password_; }

protected:
    virtual size_t nonErrorSerializedSize() const;
    virtual void nonErrorSerialize(uint8_t *buffer) const;
    virtual keyguard_error_t nonErrorDeserialize(const uint8_t *payload, const uint8_t *end);
private:
    SizedBuffer provided_password_;
};

class EnrollResponse : public KeyguardMessage {
public:
    EnrollResponse(SizedBuffer *enrolled_password_handle);
    EnrollResponse();
    ~EnrollResponse();

    const SizedBuffer *GetEnrolledPasswordHandle() const { return &enrolled_password_handle_; }

protected:
    virtual size_t nonErrorSerializedSize() const;
    virtual void nonErrorSerialize(uint8_t *buffer) const;
    virtual keyguard_error_t nonErrorDeserialize(const uint8_t *payload, const uint8_t *end);

private:
   SizedBuffer enrolled_password_handle_;
};
}

#endif // KEYGUARD_MESSAGES_H_
