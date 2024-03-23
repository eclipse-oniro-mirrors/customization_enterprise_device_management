/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef COMMON_NATIVE_INCLUDE_EDM_CONSTANTS_H
#define COMMON_NATIVE_INCLUDE_EDM_CONSTANTS_H

#include <iostream>

namespace OHOS {
namespace EDM {
namespace EdmConstants {
    static constexpr int32_t DECIMAL = 10;
    static constexpr int32_t APPID_MAX_SIZE = 200;
    static constexpr int32_t DEFAULT_USER_ID = 100;
    static constexpr int32_t ALLOWED_USB_DEVICES_MAX_SIZE = 1000;
    static constexpr int32_t STORAGE_USB_POLICY_READ_WRITE = 0;
    static constexpr int32_t STORAGE_USB_POLICY_READ_ONLY = 1;
    static constexpr int32_t STORAGE_USB_POLICY_DISABLED = 2;
    static constexpr int32_t AUTO_START_APPS_MAX_SIZE = 10;
    static constexpr int32_t SET_POLICIES_TYPE = 1;
    static constexpr int32_t SET_POLICY_TYPE = 2;
    static constexpr int32_t BLUETOOTH_WHITELIST_MAX_SIZE = 1000;
}
} // namespace EDM
} // namespace OHOS

#endif // COMMON_NATIVE_INCLUDE_EDM_CONSTANTS_H
