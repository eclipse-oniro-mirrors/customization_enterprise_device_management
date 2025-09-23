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

#ifndef INTERFACES_INNER_API_BUNDLE_MANAGER_INCLUDE_INSTALL_MARKET_APPS_SERIALIZER_H
#define INTERFACES_INNER_API_BUNDLE_MANAGER_INCLUDE_INSTALL_MARKET_APPS_SERIALIZER_H

#include <map>
#include "ipolicy_serializer.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
struct InstallMarketAppsInfo {
    // 将要安装的AG包名数组
    std::vector<std::string> bundleNames;
    // 区分安装AG、更新状态机、
    int32_t installFlag = 0;
    int32_t eventCode = 0;
    std::string singleBundleName;
};

/*
 * Policy data serializer of type int.
 */
class InstallMarketAppsSerializer : public IPolicySerializer<InstallMarketAppsInfo>,
    public DelayedSingleton<InstallMarketAppsSerializer> {
public:
    bool Deserialize(const std::string &jsonString, InstallMarketAppsInfo &dataObj) override;

    bool Serialize(const InstallMarketAppsInfo &dataObj, std::string &jsonString) override;

    bool GetPolicy(MessageParcel &data, InstallMarketAppsInfo &result) override;

    bool WritePolicy(MessageParcel &reply, InstallMarketAppsInfo &result) override;

    bool MergePolicy(std::vector<InstallMarketAppsInfo> &data, InstallMarketAppsInfo &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_BUNDLE_MANAGER_INCLUDE_INSTALL_MARKET_APPS_SERIALIZER_H
