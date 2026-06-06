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

#include "disallow_distributed_transmission_full_plugin.h"

#include <ipc_skeleton.h>
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "os_account_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<DisallowDistributedTransmissionFullPlugin>());
const std::string CONSTRAINT_DISTRIBUTED_TRANSMISSION = "constraint.distributed.transmission";

DisallowDistributedTransmissionFullPlugin::DisallowDistributedTransmissionFullPlugin()
{
    EDMLOGI("DisallowDistributedTransmissionFullPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL;
    policyName_ = PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION_FULL;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode DisallowDistributedTransmissionFullPlugin::SetOtherModulePolicy(bool policy, int32_t userId)
{
    EDMLOGI("DisallowDistributedTransmissionFullPlugin::SetDistributedTransmissionFullPolicy, "
            "policy: %{public}d", policy);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_DISTRIBUTED_TRANSMISSION);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(
        constraints, policy, userId, EdmConstants::DEFAULT_USER_ID, true);
    if (FAILED(ret)) {
        EDMLOGE("DisallowDistributedTransmissionFullPlugin::OnSetPolicy Failed, ret: %{public}d", ret);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    return ERR_OK;
}

ErrCode DisallowDistributedTransmissionFullPlugin::CheckConflictPolicy(int32_t userId)
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string policyValue;
    policyManager->GetPolicy("", PolicyName::POLICY_DISALLOWED_DISTRIBUTED_TRANSMISSION, policyValue, userId);
    if (!policyValue.empty()) {
        EDMLOGE("DisallowDistributedTransmissionFullPlugin::HasConflictPolicy policy conflict! "
                 "disallow_distributed_transmission is already set");
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
