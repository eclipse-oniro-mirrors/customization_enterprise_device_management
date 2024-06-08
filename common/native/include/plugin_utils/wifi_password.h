/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef COMMON_NATIVE_INCLUDE_WIFI_PASSWORD_H
#define COMMON_NATIVE_INCLUDE_WIFI_PASSWORD_H

#include "edm_utils.h"

namespace OHOS {
namespace EDM {
struct WifiPassword {
    char* preSharedKey = nullptr;
    size_t preSharedKeySize = 0;
    char* password = nullptr;
    size_t passwordSize = 0;
    char* wepKey = nullptr;
    size_t wepKeySize = 0;

    ~WifiPassword()
    {
        EdmUtils::ClearCharArray(preSharedKey, preSharedKeySize);
        EdmUtils::ClearCharArray(password, passwordSize);
        EdmUtils::ClearCharArray(wepKey, wepKeySize);
        preSharedKeySize = 0;
        passwordSize = 0;
        wepKeySize = 0;
    }
};
}
}
#endif // COMMON_NATIVE_INCLUDE_WIFI_PASSWORD_H