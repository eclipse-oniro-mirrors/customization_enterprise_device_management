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

#ifndef INTERFACES_INNER_API_KITS_SYSTEM_MANAGER_INCLUDE_UPDATE_POLICY_UTILS_H
#define INTERFACES_INNER_API_KITS_SYSTEM_MANAGER_INCLUDE_UPDATE_POLICY_UTILS_H

#include <string>
#include <vector>

#include "message_parcel.h"

#include "edm_constants.h"
#include "update_policy_info.h"

namespace OHOS {
namespace EDM {
enum class UpgradeStatus {
    NO_UPGRADE_PACKAGE = -4,
    UPGRADE_WAITING = -3,
    UPGRADING = -2,
    UPGRADE_FAILURE = -1,
    UPGRADE_SUCCESS = 0
};

enum class GetUpdateInfo {
    UPDATE_RESULT = 0,
    UPDATE_AUTH_DATA = 1
};

struct UpgradeResult {
    std::string version;
    UpgradeStatus status = UpgradeStatus::UPGRADE_SUCCESS;
    int32_t errorCode = 0;
    std::string errorMessage;
};

class UpdatePolicyUtils {
public:
    static bool ProcessUpdatePolicyType(int32_t type, UpdatePolicyType &updatePolicyType);
    static void ProcessPackageType(int32_t type, PackageType &packageType);
    static void ProcessUpgradeStatus(int32_t status, UpgradeStatus &upgradeStatus);
    static void ProcessOtaPolicyType(int32_t type, OtaPolicyType &otaPolicyType);
    static void WriteUpdatePolicy(MessageParcel &data, const UpdatePolicy &updatePolicy);
    static void ReadUpdatePolicy(MessageParcel &data, UpdatePolicy &updatePolicy);
    static void WriteUpgradePackageInfo(MessageParcel &data, UpgradePackageInfo &packageInfo);
    static void ReadUpgradePackageInfo(MessageParcel &data, UpgradePackageInfo &packageInfo);
    static void WriteUpgradeResult(MessageParcel &data, const UpgradeResult &result);
    static void ReadUpgradeResult(MessageParcel &data, UpgradeResult &result);
    static void ClosePackagesFileHandle(std::vector<Package> &packages);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_KITS_SYSTEM_MANAGER_INCLUDE_UPDATE_POLICY_UTILS_H
