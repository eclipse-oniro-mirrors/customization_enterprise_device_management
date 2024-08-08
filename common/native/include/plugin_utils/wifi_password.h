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

namespace OHOS {
namespace EDM {
struct WifiPassword {
    char* preSharedKey;
    size_t preSharedKeySize = 0;
    char* password;
    size_t passwordSize = 0;
    char* wepKey;
    size_t wepKeySize = 0;

    WifiPassword()
    {
        preSharedKey = new char[1]{'\0'};
        password = new char[1]{'\0'};
        wepKey = new char[1]{'\0'};
    }

    void clear()
    {
        if (preSharedKey != nullptr) {
            memset_s(preSharedKey, preSharedKeySize, '\0', preSharedKeySize);
        }
        if (password != nullptr) {
            memset_s(password, passwordSize, '\0', passwordSize);
        }
        if (wepKey != nullptr) {
            memset_s(wepKey, wepKeySize, '\0', wepKeySize);
        }
    }
};
}
}
#endif // COMMON_NATIVE_INCLUDE_WIFI_PASSWORD_H