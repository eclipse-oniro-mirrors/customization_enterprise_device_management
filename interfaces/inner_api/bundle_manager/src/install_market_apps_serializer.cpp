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

#include "install_market_apps_serializer.h"

namespace OHOS {
namespace EDM {
bool InstallMarketAppsSerializer::Deserialize(const std::string &jsonString, InstallMarketAppsInfo &config)
{
    return true;
}

bool InstallMarketAppsSerializer::Serialize(const InstallMarketAppsInfo &config, std::string &jsonString)
{
    return true;
}

bool InstallMarketAppsSerializer::GetPolicy(MessageParcel &data, InstallMarketAppsInfo &result)
{
    data.ReadStringVector(&result.bundleNames);
    result.installFlag = data.ReadInt32();
    result.eventCode = data.ReadInt32();
    result.singleBundleName = data.ReadString();
    return true;
}

bool InstallMarketAppsSerializer::WritePolicy(MessageParcel &reply, InstallMarketAppsInfo &result)
{
    return true;
}

bool InstallMarketAppsSerializer::MergePolicy(std::vector<InstallMarketAppsInfo> &data, InstallMarketAppsInfo &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS