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

#include "upgrade_package_info_serializer.h"

namespace OHOS {
namespace EDM {
bool UpgradePackageInfoSerializer::Deserialize(const std::string &jsonString, UpgradePackageInfo &dataObj)
{
    return true;
}

bool UpgradePackageInfoSerializer::Serialize(const UpgradePackageInfo &dataObj, std::string &jsonString)
{
    if (!dataObj.packages.empty()) {
        jsonString = "true";
    }
    return true;
}

bool UpgradePackageInfoSerializer::GetPolicy(MessageParcel &data, UpgradePackageInfo &result)
{
    UpdatePolicyUtils::ReadUpgradePackageInfo(data, result);
    return true;
}

bool UpgradePackageInfoSerializer::WritePolicy(MessageParcel &reply, UpgradePackageInfo &result)
{
    return true;
}

bool UpgradePackageInfoSerializer::MergePolicy(std::vector<UpgradePackageInfo> &data,
    UpgradePackageInfo &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS