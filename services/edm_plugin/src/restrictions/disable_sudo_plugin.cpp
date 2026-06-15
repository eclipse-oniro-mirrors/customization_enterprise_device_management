/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "disable_sudo_plugin.h"

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
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisableSudoPlugin>());
const std::string CONSTRAINT_SUDO = "constraint.sudo";

DisableSudoPlugin::DisableSudoPlugin()
{
    EDMLOGI("DisableSudoPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOWED_SUDO;
    policyName_ = PolicyName::POLICY_DISABLED_SUDO;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode DisableSudoPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisableSudoPlugin::SetSudoPolicy, policy: %{public}d", data);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_SUDO);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(constraints, data, userId,
        EdmConstants::DEFAULT_USER_ID, true);
    EDMLOGI("DisableSudoPlugin::SetSudoPolicy, SetSpecificOsAccountConstraints ret: %{public}d", ret);
    return ret;
}

ErrCode DisableSudoPlugin::CheckConflictPolicy(int32_t userId)
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string policyValue;
    policyManager->GetPolicy("", PolicyName::POLICY_DISALLOWED_DEVICE_SUDO, policyValue,
        EdmConstants::DEFAULT_USER_ID);
    return policyValue == EdmConstants::CONST_TRUE ? EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED : ERR_OK;
}
} // namespace EDM
} // namespace OHOS