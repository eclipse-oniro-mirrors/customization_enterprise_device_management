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

#ifndef ENTERPRISE_DEVICE_MANAGEMENT_WIFI_POLICY_UTILS_H
#define ENTERPRISE_DEVICE_MANAGEMENT_WIFI_POLICY_UTILS_H

#include "edm_errors.h"
#include "wifi_id.h"

namespace OHOS {
namespace EDM {
class WifiPolicyUtils {
public:
    static ErrCode SetWifiAccessList(std::vector<WifiId> data, bool isAllowed);
    static ErrCode AddWifiListPolicy(std::vector<WifiId> &data, std::vector<WifiId> &currentData,
        std::vector<WifiId> &mergeData, int32_t userId, bool isAllowed);
    static ErrCode RemoveWifiListPolicy(std::vector<WifiId> &data, std::vector<WifiId> &currentData,
        std::vector<WifiId> &mergeData, int32_t userId, bool isAllowed);
    static bool CheckWifiId(std::vector<WifiId> &data, bool isAllowed);
    static bool HasConflictPolicy(bool isAllowed);
};
} // namespace EDM
} // namespace OHOS

#endif //ENTERPRISE_DEVICE_MANAGEMENT_WIFI_POLICY_UTILS_H
