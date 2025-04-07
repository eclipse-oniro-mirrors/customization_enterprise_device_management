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

#include "update_policy_utils.h"

#include <unistd.h>

#include "securec.h"

#include "edm_constants.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {

constexpr uint32_t MAX_PACKAGES_SIZE = 10;
bool UpdatePolicyUtils::ProcessUpdatePolicyType(int32_t type, UpdatePolicyType &updatePolicyType)
{
    if (type >= static_cast<int32_t>(UpdatePolicyType::DEFAULT) &&
        type <= static_cast<int32_t>(UpdatePolicyType::POSTPONE)) {
        updatePolicyType = static_cast<UpdatePolicyType>(type);
        return true;
    }
    return false;
}

void UpdatePolicyUtils::ProcessPackageType(int32_t type, PackageType &packageType)
{
    packageType = PackageType::UNKNOWN;
    if (type == static_cast<int32_t>(PackageType::FIRMWARE)) {
        packageType = static_cast<PackageType>(type);
    }
}

void UpdatePolicyUtils::ProcessUpgradeStatus(int32_t status, UpgradeStatus &upgradeStatus)
{
    upgradeStatus = UpgradeStatus::UPGRADE_SUCCESS;
    if (status >= static_cast<int32_t>(UpgradeStatus::NO_UPGRADE_PACKAGE) &&
        status <= static_cast<int32_t>(UpgradeStatus::UPGRADE_SUCCESS)) {
        upgradeStatus = static_cast<UpgradeStatus>(status);
    }
}

void UpdatePolicyUtils::WriteUpdatePolicy(MessageParcel &data, const UpdatePolicy &updatePolicy)
{
    data.WriteInt32(static_cast<int32_t>(updatePolicy.type));
    data.WriteString(updatePolicy.version);
    data.WriteInt64(updatePolicy.installTime.latestUpdateTime);
    data.WriteInt64(updatePolicy.installTime.delayUpdateTime);
    data.WriteInt64(updatePolicy.installTime.installWindowStart);
    data.WriteInt64(updatePolicy.installTime.installWindowEnd);
    data.WriteBool(updatePolicy.disableSystemOtaUpdate);
}

void UpdatePolicyUtils::ReadUpdatePolicy(MessageParcel &data, UpdatePolicy &updatePolicy)
{
    UpdatePolicyUtils::ProcessUpdatePolicyType(data.ReadInt32(), updatePolicy.type);
    data.ReadString(updatePolicy.version);
    data.ReadInt64(updatePolicy.installTime.latestUpdateTime);
    data.ReadInt64(updatePolicy.installTime.delayUpdateTime);
    data.ReadInt64(updatePolicy.installTime.installWindowStart);
    data.ReadInt64(updatePolicy.installTime.installWindowEnd);
    data.ReadBool(updatePolicy.disableSystemOtaUpdate);
}

void UpdatePolicyUtils::WriteUpgradePackageInfo(MessageParcel &data, UpgradePackageInfo &packageInfo)
{
    data.WriteString(packageInfo.version);
    data.WriteUint32(packageInfo.packages.size());
    for (auto package : packageInfo.packages) {
        data.WriteInt32(static_cast<int32_t>(package.type));
        data.WriteString(package.path);
        data.WriteFileDescriptor(package.fd);
    }
    data.WriteString(packageInfo.description.notify.installTips);
    data.WriteString(packageInfo.description.notify.installTipsDetail);
    data.WriteUint32(packageInfo.authInfoSize);
    if (packageInfo.authInfoSize >= EdmConstants::AUTH_INFO_MAX_SIZE) {
        EDMLOGE("UpdatePolicyUtils::WriteUpgradePackageInfo auth info too long.");
        return;
    }
    data.WriteCString(packageInfo.authInfo);
    errno_t err = memset_s(packageInfo.authInfo, sizeof(packageInfo.authInfo), 0, sizeof(packageInfo.authInfo));
    if (err != EOK) {
        EDMLOGE("UpdatePolicyUtils::WriteUpgradePackageInfo memset_s failed: %{public}d.", err);
    }
}

void UpdatePolicyUtils::ReadUpgradePackageInfo(MessageParcel &data, UpgradePackageInfo &packageInfo)
{
    data.ReadString(packageInfo.version);
    size_t size = data.ReadUint32();
    if (size > MAX_PACKAGES_SIZE) {
        return;
    }
    for (size_t i = 0; i < size; i++) {
        Package package;
        ProcessPackageType(data.ReadInt32(), package.type);
        data.ReadString(package.path);
        package.fd = data.ReadFileDescriptor();
        packageInfo.packages.push_back(package);
    }
    data.ReadString(packageInfo.description.notify.installTips);
    data.ReadString(packageInfo.description.notify.installTipsDetail);
    data.ReadUint32(packageInfo.authInfoSize);
    if (packageInfo.authInfoSize >= EdmConstants::AUTH_INFO_MAX_SIZE) {
        EDMLOGE("UpdatePolicyUtils::ReadUpgradePackageInfo auth info too long.");
        return;
    }
    errno_t err = memcpy_s(packageInfo.authInfo, sizeof(packageInfo.authInfo), data.ReadCString(),
        packageInfo.authInfoSize);
    if (err != EOK) {
        EDMLOGE("UpdatePolicyUtils::ReadUpgradePackageInfo memset_s failed: %{public}d.", err);
    }
}

void UpdatePolicyUtils::WriteUpgradeResult(MessageParcel &data, const UpgradeResult &result)
{
    data.WriteString(result.version);
    data.WriteInt32(static_cast<int32_t>(result.status));
    data.WriteInt32(result.errorCode);
    data.WriteString(result.errorMessage);
}

void UpdatePolicyUtils::ReadUpgradeResult(MessageParcel &data, UpgradeResult &result)
{
    data.ReadString(result.version);
    ProcessUpgradeStatus(data.ReadInt32(), result.status);
    data.ReadInt32(result.errorCode);
    data.ReadString(result.errorMessage);
}

void UpdatePolicyUtils::ClosePackagesFileHandle(std::vector<Package> &packages)
{
    for (auto &package : packages) {
        if (package.fd >= 0) {
            if (close(package.fd) != 0) {
                EDMLOGW("ClosePackagesFileHandle failed");
            }
            package.fd = -1;
        }
    }
}
} // namespace EDM
} // namespace OHOS