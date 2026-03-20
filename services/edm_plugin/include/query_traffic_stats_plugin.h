/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_QUERY_TRAFFIC_STATS_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_QUERY_TRAFFIC_STATS_PLUGIN_H

#include <string>

#include "iedm_bundle_manager.h"
#include "iplugin.h"
#include "net_stats_utils.h"

namespace OHOS {
namespace EDM {
class QueryTrafficStatsPlugin : public IPlugin {
public:
    QueryTrafficStatsPlugin();
    ErrCode OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
        HandlePolicyData &policyData, int32_t userId) override
    {
        return ERR_OK;
    };

    void OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName, bool isGlobalChanged,
        int32_t userId) override {};

    ErrCode OnAdminRemove(const std::string &adminName, const std::string &policyData,
        const std::string &mergeData, int32_t userId) override
    {
        return ERR_OK;
    };

    void OnAdminRemoveDone(const std::string &adminName, const std::string &currentJsonData,
        int32_t userId) override {};
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
        int32_t userId) override;
private:
    ErrCode QueryTrafficStatsByUidNetwork(int32_t uid, const NetStatsNetwork &networkInfo,
        NetStatsInfo &netStatsInfo);
    static std::shared_ptr<IEdmBundleManager> bundleMgr_;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_QUERY_TRAFFIC_STATS_PLUGIN_H
