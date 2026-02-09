/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_SYSTEM_MANAGER_INCLUDE_UPGRADE_PACKAGE_INFO_SERIALIZER_H
#define INTERFACES_INNER_API_SYSTEM_MANAGER_INCLUDE_UPGRADE_PACKAGE_INFO_SERIALIZER_H

#include "singleton.h"

#include "ipolicy_serializer.h"
#include "update_policy_utils.h"

namespace OHOS {
namespace EDM {
/*
* Policy data serializer of type UpgradePackageInfo.
*/
class UpgradePackageInfoSerializer : public IPolicySerializer<UpgradePackageInfo>,
    public DelayedSingleton<UpgradePackageInfoSerializer> {
public:
    bool Deserialize(const std::string &jsonString, UpgradePackageInfo &dataObj) override;

    bool Serialize(const UpgradePackageInfo &dataObj, std::string &jsonString) override;

    bool GetPolicy(MessageParcel &data, UpgradePackageInfo &result) override;

    bool WritePolicy(MessageParcel &reply, UpgradePackageInfo &result) override;

    bool MergePolicy(std::vector<UpgradePackageInfo> &data, UpgradePackageInfo &result) override;
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_SYSTEM_MANAGER_INCLUDE_UPGRADE_PACKAGE_INFO_SERIALIZER_H