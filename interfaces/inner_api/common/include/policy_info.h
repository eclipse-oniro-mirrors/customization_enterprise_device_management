/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_INCLUDE_POLICY_INFO_H
#define INTERFACES_INNER_API_INCLUDE_POLICY_INFO_H

#include <algorithm>
#include <string>

namespace OHOS {
namespace EDM {
enum {
    SET_DATETIME = 1001,
    GET_DEVICE_SERIAL = 1002,
    GET_DISPLAY_VERSION = 1003,
    GET_DEVICE_NAME = 1004,
    RESET_FACTORY = 1005,
    DISALLOW_ADD_LOCAL_ACCOUNT = 1006,
    IS_WIFI_ACTIVE = 1007,
    GET_NETWORK_INTERFACES = 1008,
    GET_IP_ADDRESS = 1009,
    GET_MAC = 1010,
    POLICY_CODE_END = 3000,
};

#define POLICY_CODE_TO_NAME(ENUM_CODE, POLICY_NAME) do { \
    POLICY_NAME = (#ENUM_CODE); \
    std::transform((POLICY_NAME).begin(), (POLICY_NAME).end(), (POLICY_NAME).begin(), ::tolower); \
} while (0)
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_INCLUDE_POLICY_INFO_H
