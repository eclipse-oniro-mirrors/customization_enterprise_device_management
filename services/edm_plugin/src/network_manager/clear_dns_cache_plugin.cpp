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

#include "clear_dns_cache_plugin.h"

#include "netsys_controller.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
namespace {
constexpr int32_t FLUSH_DNS_CACHE_NOT_EXIST = -2; // no dns cache exists for the requested netId
} // namespace

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<ClearDnsCachePlugin>());

ClearDnsCachePlugin::ClearDnsCachePlugin()
{
    EDMLOGI("ClearDnsCachePlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::CLEAR_DNS_CACHE;
    policyName_ = PolicyName::POLICY_CLEAR_DNS_CACHE;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode ClearDnsCachePlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("ClearDnsCachePlugin OnHandlePolicy");
    int32_t netId = 0;
    if (!data.ReadInt32(netId)) {
        EDMLOGE("ClearDnsCachePlugin: read netId failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    if (netId < 0) {
        EDMLOGE("ClearDnsCachePlugin: invalid netId=%{public}d", netId);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    int32_t ret = FlushDnsCache(netId);
    if (ret == FLUSH_DNS_CACHE_NOT_EXIST) {
        EDMLOGE("ClearDnsCachePlugin: no dns cache for netId=%{public}d", netId);
        return EdmReturnErrCode::DNS_CACHE_NOT_EXIST;
    }
    if (ret != ERR_OK) {
        EDMLOGE("ClearDnsCachePlugin: FlushDnsCache failed, netId=%{public}d, ret=%{public}d", netId, ret);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    EDMLOGI("ClearDnsCachePlugin: FlushDnsCache success, netId=%{public}d", netId);
    return ERR_OK;
}

int32_t ClearDnsCachePlugin::FlushDnsCache(int32_t netId)
{
    return NetManagerStandard::NetsysController::GetInstance().FlushDnsCache(netId);
}
} // namespace EDM
} // namespace OHOS
