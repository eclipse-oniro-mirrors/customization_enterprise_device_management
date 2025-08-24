/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMMON_NATIVE_INCLUDE_APN_PASSWORD_H
#define COMMON_NATIVE_INCLUDE_APN_PASSWORD_H

#include "edm_utils.h"
#include <climits>

namespace OHOS {
namespace EDM {
struct ApnPassword {
    char* password = nullptr;
    size_t passwordSize = 0;
    static constexpr size_t MAX_PASSWORD_SIZE = UINT8_MAX;

    ApnPassword() = default;

    ~ApnPassword()
    {
        EdmUtils::ClearCharArray(password, passwordSize);
        passwordSize = 0;
    }

    ApnPassword(const ApnPassword&) = delete;

    ApnPassword& operator=(const ApnPassword&) = delete;

    ApnPassword(ApnPassword&& other) noexcept
    {
        password = other.password;
        passwordSize = other.passwordSize;
        other.password = nullptr;
        other.passwordSize = 0;
    }

    ApnPassword& operator=(ApnPassword&& other) noexcept
    {
        if (this != &other) {
            EdmUtils::ClearCharArray(password, passwordSize);
            password = other.password;
            passwordSize = other.passwordSize;
            other.password = nullptr;
            other.passwordSize = 0;
        }
        return *this;
    }
};
}
}
#endif // COMMON_NATIVE_INCLUDE_APN_PASSWORD_H