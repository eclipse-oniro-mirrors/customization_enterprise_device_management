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

#include "query_bundle_stats_infos_query.h"

#include "bundle_active_client.h"
#include "bundle_active_package_stats.h"
#include "bundle_active_period_stats.h"

#include "edm_log.h"

namespace OHOS {
namespace EDM {
std::string QueryBundleStatsInfosQuery::GetPolicyName()
{
    return PolicyName::POLICY_QUERY_BUNDLE_STATS_INFOS;
}

std::string QueryBundleStatsInfosQuery::GetPermission(IPlugin::PermissionType, const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION;
}

ErrCode QueryBundleStatsInfosQuery::QueryPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("QueryBundleStatsInfosQuery::QueryPolicy");
    int64_t startTime = 0;
    if (!data.ReadInt64(startTime)) {
        EDMLOGE("QueryBundleStatsInfo QueryPolicy Read startTime failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int64_t endTime = 0;
    if (!data.ReadInt64(endTime)) {
        EDMLOGE("QueryBundleStatsInfo QueryPolicy Read endTime failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t accountId = 0;
    if (!data.ReadInt32(accountId)) {
        EDMLOGE("QueryBundleStatsInfo QueryPolicy Read accountId failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t intervalType = 0;
    std::vector<BundleActivePackageStats> bundleActivePackageStats;
    ErrCode ret = DeviceUsageStats::BundleActiveClient::GetInstance().QueryBundleStatsInfoByInterval(
        bundleActivePackageStats, intervalType, startTime, endTime, accountId);
    if (ret != ERR_OK) {
        EDMLOGE("QueryBundleStatsInfo QueryPolicy QueryBundleStatsInfoByInterval failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    size_t size = bundleActivePackageStats.size();
    reply.WriteUint32(size);
    for (auto &stat: bundleActivePackageStats) {
        reply.WriteString(stat.bundleName_);
        reply.WriteInt64(stat.totalInFrontTime_);
        reply.WriteInt32(stat.appIndex_);
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
