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

#ifndef NATIVE_GATEKEEPER_FILE_IO_H
#define NATIVE_GATEKEEPER_FILE_IO_H

#include <gatekeeper/soft_gatekeeper.h>

namespace gatekeeper {

class NativeGateKeeperFileIo : public ::gatekeeper::GateKeeperFileIo {
public:
    virtual void Write(const char *filename, const uint8_t *bytes, size_t length) {
        // TODO
    }

    virtual size_t Read(const char *filename, UniquePtr<uint8_t> *bytes) const {
        // TODO
        return 0;
    }
private:
};
}

#endif // NATIVE_GATEKEEPER_FILE_IO_H
