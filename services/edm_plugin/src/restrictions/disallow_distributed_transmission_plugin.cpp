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

#include "disallow_distributed_transmission_plugin.h"

#include <ipc_skeleton.h>
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_os_account_manager_impl.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "os_account_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<DisallowDistributedTransmissionPlugin>());
const std::string CONSTRAINT_DISTRIBUTED_TRANSMISSION = "constraint.distributed.transmission.outgoing";

DisallowDistributedTransmissionPlugin::DisallowDistributedTransmissionPlugin()
{
    EDMLOGI("DisallowDistributedTransmissionPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION;
    policyName_ = PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode DisallowDistributedTransmissionPlugin::SetOtherModulePolicy(bool policy, int32_t userId)
{
    EDMLOGI("DisallowDistributedTransmissionPlugin::SetDistributedTransmissionPolicy, "
            "policy: %{public}d", policy);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_DISTRIBUTED_TRANSMISSION);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(
        constraints, policy, userId, EdmConstants::DEFAULT_USER_ID, true);
    if (FAILED(ret)) {
        EDMLOGE("DisallowDistributedTransmissionPlugin::OnSetPolicy Failed, ret: %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (!policy) {
        ClearAllowedCollaborationServiceBundles(userId);
    }
    return ERR_OK;
}

ErrCode DisallowDistributedTransmissionPlugin::ClearAllowedCollaborationServiceBundles(int32_t userId)
{
    EDMLOGI("DisallowDistributedTransmissionPlugin::ClearAllowedDistributeAbilityConnPolicy");
    auto policyManager = IPolicyManager::GetInstance();
    std::unordered_map<std::string, std::string> adminListMap;
    ErrCode ret = policyManager->GetAdminByPolicyName(
        PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES, adminListMap, userId);
    if (ret != ERR_OK || adminListMap.empty()) {
        EDMLOGI("DisallowDistributedTransmissionPlugin No allowed list policy to clear");
        return ERR_OK;
    }
    for (const auto &admin : adminListMap) {
        EDMLOGI("DisallowDistributedTransmissionPlugin clear allowed list for: %{public}d, %{public}s",
            userId, admin.first.c_str());
        ErrCode retSet = policyManager->SetPolicy(admin.first,
            PolicyName::POLICY_ALLOWED_COLLABORATION_SERVICE_BUNDLES, "", "", userId);
        if (retSet != ERR_OK) {
            EDMLOGW("DisallowDistributedTransmissionPlugin clear allowed list failed: %{public}d  %{public}s",
                ret, admin.first.c_str());
        }
    }
    return ERR_OK;
}

ErrCode DisallowDistributedTransmissionPlugin::CheckConflictPolicy(int32_t userId)
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string policyValue;
    policyManager->GetPolicy("", PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL, policyValue, userId);
    if (!policyValue.empty()) {
        EDMLOGE("DisallowDistributedTransmissionPlugin::HasConflictPolicy policy conflict! "
                 "disallow_distributed_transmission_full is already set");
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
