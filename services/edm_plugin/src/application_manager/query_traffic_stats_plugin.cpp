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

#include "query_traffic_stats_plugin.h"

#include <system_ability_definition.h>

#include "edm_bundle_manager_impl.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_sys_manager.h"
#include "iext_info_manager.h"
#include "iplugin_manager.h"
#include "net_all_capabilities.h"
#include "net_stats_client.h"
#include "parcel_macro.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<QueryTrafficStatsPlugin>());

std::shared_ptr<IEdmBundleManager> QueryTrafficStatsPlugin::bundleMgr_ = std::make_shared<EdmBundleManagerImpl>();
std::shared_ptr<IExternalManagerFactory> QueryTrafficStatsPlugin::externalManagerFactory_ =
    std::make_shared<ExternalManagerFactory>();

QueryTrafficStatsPlugin::QueryTrafficStatsPlugin()
{
    policyCode_ = EdmInterfaceCode::QUERY_TRAFFIC_STATS;
    policyName_ = PolicyName::POLICY_QUERY_TRAFFIC_STATS;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

ErrCode QueryTrafficStatsPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("QueryTrafficStatsPlugin OnGetPolicy");

    NetStatsNetwork networkInfo;
    NetStatsNetwork::Unmarshalling(data, networkInfo);
    if (networkInfo.type > static_cast<uint32_t>(NetManagerStandard::NetBearType::BEARER_WIFI) ||
        networkInfo.type < static_cast<uint32_t>(NetManagerStandard::NetBearType::BEARER_CELLULAR)) {
        EDMLOGE("QueryTrafficStatsPlugin::OnGetPolicy networkInfo.type invalid");
        reply.WriteInt32(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (networkInfo.startTime < 0 || networkInfo.endTime < 0 || networkInfo.startTime > networkInfo.endTime) {
        EDMLOGE("QueryTrafficStatsPlugin::OnGetPolicy networkInfo time invalid");
        reply.WriteInt32(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    int32_t currentUserId = externalManagerFactory_->CreateOsAccountManager()->GetCurrentUserId();
    if (currentUserId < 0) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (networkInfo.accountId != currentUserId) {
        EDMLOGE("QueryTrafficStatsPlugin::OnGetPolicy accountId isn't current userId.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    uint32_t uid = 0;
    if (!GetAppUid(networkInfo, uid)) {
        EDMLOGE("QueryTrafficStatsPlugin::OnGetPolicy getUid failed");
        reply.WriteInt32(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    NetStatsInfo netStatsInfo;
    ErrCode ret = QueryTrafficStatsByUidNetwork(uid, networkInfo, netStatsInfo);
    if (ret != ERR_OK) {
        EDMLOGE("GetTrafficStats failed, ret = %{public}d", ret);
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    netStatsInfo.Marshalling(reply);
    return ERR_OK;
}

// LCOV_EXCL_START
bool QueryTrafficStatsPlugin::GetAppUid(const NetStatsNetwork &networkInfo, uint32_t &uid)
{
    auto it = IExtInfoManager::appUidMap.find(networkInfo.bundleName);
    if (it != IExtInfoManager::appUidMap.end()) {
        uid = it->second;
        if (networkInfo.appIndex != 0) {
            EDMLOGE("QueryTrafficStatsPlugin::GetAppUid appIndex param error");
            return false;
        }
        return true;
    }
    int32_t uidTemp = bundleMgr_->GetApplicationUid(networkInfo.bundleName, networkInfo.accountId,
        networkInfo.appIndex);
    if (uidTemp > 0) {
        uid = static_cast<uint32_t>(uidTemp);
        return true;
    }
    if (networkInfo.appIndex == 0) {
        AppExecFwk::BundleInfo bundleInfo;
        bool bundleRet = bundleMgr_->GetBundleInfoV9(networkInfo.bundleName,
            static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_DEFAULT), bundleInfo,
            networkInfo.accountId);
        if (!bundleRet) {
            EDMLOGE("QueryTrafficStatsPlugin GetBundleInfo false");
            return false;
        }
        uid = static_cast<uint32_t>(bundleInfo.uid);
        return true;
    }
    return false;
}
// LCOV_EXCL_STOP

// LCOV_EXCL_START
ErrCode QueryTrafficStatsPlugin::QueryTrafficStatsByUidNetwork(uint32_t uid,
    const NetStatsNetwork &networkInfo, NetStatsInfo &netStatsInfo)
{
    sptr<NetManagerStandard::NetStatsNetwork> netStatsNetwork =
        new (std::nothrow) NetManagerStandard::NetStatsNetwork();
    if (netStatsNetwork == nullptr) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    netStatsNetwork->type_ = networkInfo.type;
    netStatsNetwork->startTime_ = static_cast<uint64_t>(networkInfo.startTime);
    netStatsNetwork->endTime_ = static_cast<uint64_t>(networkInfo.endTime);
    netStatsNetwork->simId_ = networkInfo.simId;
    std::vector<NetManagerStandard::NetStatsInfoSequence> netStatsInfoSequences;
    ErrCode ret = NetManagerStandard::NetStatsClient::GetInstance().GetTrafficStatsByUidNetwork(netStatsInfoSequences,
        uid, netStatsNetwork);
    if (ret != ERR_OK) {
        EDMLOGE("GetTrafficStatsByUidNetwork failed, ret = %{public}d", ret);
        return ret;
    }
    for (const auto &item : netStatsInfoSequences) {
        netStatsInfo.rxBytes += item.info_.rxBytes_;
        netStatsInfo.txBytes += item.info_.txBytes_;
        netStatsInfo.rxPackets += item.info_.rxPackets_;
        netStatsInfo.txPackets += item.info_.txPackets_;
    }
    EDMLOGI("QueryTrafficStatsByUidNetwork success");
    return ERR_OK;
}
// LCOV_EXCL_STOP
} // namespace EDM
} // namespace OHOS
