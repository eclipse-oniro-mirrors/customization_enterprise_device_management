/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include "get_installed_bundle_storage_stats_query.h"

#include <system_ability_definition.h>

#include "bundle_storage_info.h"
#include "edm_errors.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
 #include "permission_checker.h"

namespace OHOS {
namespace EDM {
const size_t STORAGE_STATS_SIZE = 2;
const int32_t APP_DATA_SIZE_INDEX = 0;
const int32_t BUNDLE_DATA_SIZE_INDEX = 1;
    
std::string GetInstalledBundleStorageStatsQuery::GetPolicyName()
{
    return PolicyName::POLICY_BUNDLE_STORAGE_STATS;
}

std::string GetInstalledBundleStorageStatsQuery::GetPermission(IPlugin::PermissionType,
    const std::string &permissionTag)
{
    return EdmPermission::PERMISSION_ENTERPRISE_GET_ALL_BUNDLE_INFO;
}

ErrCode GetInstalledBundleStorageStatsQuery::QueryPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    uint32_t dataSize = data.ReadUint32();
 	if (dataSize > EdmConstants::POLICIES_MAX_SIZE) {
 	    EDMLOGI("GetInstalledBundleStorageStatsQuery QueryPolicy data size = %{public}d", dataSize);
 	    return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
 	}
    std::vector<std::string> bundles;
    if (!data.ReadStringVector(&bundles)) {
        EDMLOGI("GetInstalledBundleStorageStatsQuery read string vector error");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (bundles.size() > EdmConstants::POLICIES_MAX_SIZE) {
        EDMLOGI("GetInstalledBundleStorageStatsQuery QueryPolicy data size error");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    std::vector<OHOS::AppExecFwk::BundleStorageStats> bundleStats;
    if (FAILED(GetBundleStorageStatsFromBms(bundles, userId, bundleStats))) {
        EDMLOGE("GetInstalledBundleStorageStatsQuery GetBundleStorageStatsFromBms failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (FAILED(AddResultToReply(bundleStats, reply))) {
        EDMLOGE("GetInstalledBundleStorageStatsQuery AddResultToReply failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode GetInstalledBundleStorageStatsQuery::GetBundleStorageStatsFromBms(std::vector<std::string> &bundles,
    int32_t accountId, std::vector<OHOS::AppExecFwk::BundleStorageStats> &bundleStats)
{
    EDMLOGI("GetInstalledBundleStorageStatsQuery QueryPolicy accountId = %{public}d", accountId);
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    sptr<AppExecFwk::IBundleMgr> proxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (!proxy) {
        EDMLOGE("GetInstalledBundleStorageStatsQuery QueryPolicy getBundleMgr failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode ret = proxy->BatchGetBundleStats(bundles, accountId, bundleStats);
    if (ret != ERR_OK) {
        EDMLOGE("GetInstalledBundleStorageStatsQuery QueryPolicy BatchGetBundleStats failed ret = %{public}d.", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode GetInstalledBundleStorageStatsQuery::AddResultToReply(
    std::vector<OHOS::AppExecFwk::BundleStorageStats> &bundleStats, MessageParcel &reply)
{
    if (bundleStats.size() > EdmConstants::POLICIES_MAX_SIZE) {
        EDMLOGE("AddResultToReply size error");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteUint32(bundleStats.size());
    for (auto &bundleStorageStats : bundleStats) {
        BundleStorageInfo bundleStorageInfo;
        bundleStorageInfo.bundleName = bundleStorageStats.bundleName;
        if (bundleStorageStats.bundleStats.size() < STORAGE_STATS_SIZE) {
            EDMLOGE("GetInstalledBundleStorageStatsQuery bundleStats size error");
            bundleStorageInfo.Marshalling(reply);
            continue;
        }
        bundleStorageInfo.appSize = bundleStorageStats.bundleStats[APP_DATA_SIZE_INDEX];
        bundleStorageInfo.dataSize = bundleStorageStats.bundleStats[BUNDLE_DATA_SIZE_INDEX];
        bundleStorageInfo.Marshalling(reply);
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS