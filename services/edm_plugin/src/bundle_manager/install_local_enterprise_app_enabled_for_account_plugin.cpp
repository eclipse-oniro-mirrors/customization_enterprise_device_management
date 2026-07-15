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

#include "install_local_enterprise_app_enabled_for_account_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "install_local_enterprise_app_policy_utils.h"
#include "ipolicy_manager.h"
#include "os_account_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<InstallLocalEnterpriseAppEnabledForAccountPlugin>());
const std::string CONSTRAINT_LOCAL_INSTALL = "constraint.enterprise.bundles.local.install.disallow";

InstallLocalEnterpriseAppEnabledForAccountPlugin::InstallLocalEnterpriseAppEnabledForAccountPlugin()
{
    EDMLOGI("InstallLocalEnterpriseAppEnabledForAccountPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT;
    policyName_ = PolicyName::POLICY_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED_FOR_ACCOUNT;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM, IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
}

ErrCode InstallLocalEnterpriseAppEnabledForAccountPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("InstallLocalEnterpriseAppEnabledForAccountPlugin SetOtherModulePolicy data = %{public}d", data);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_LOCAL_INSTALL);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(constraints, data, userId,
        EdmConstants::DEFAULT_USER_ID, true);
    if (FAILED(ret)) {
        EDMLOGE("InstallLocalEnterpriseAppEnabledForAccountPlugin SetSpecificOsAccountConstraints failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

void InstallLocalEnterpriseAppEnabledForAccountPlugin::OnHandlePolicyDone(
    bool data, bool isGlobalChanged, int32_t userId)
{
    EDMLOGI("InstallLocalEnterpriseAppEnabledForAccountPlugin OnHandlePolicyDone...");
    if (!isGlobalChanged) {
        return;
    }
    InstallLocalEnterpriseAppPolicyUtils::UpdatePolicyByUser(userId);
    InstallLocalEnterpriseAppPolicyUtils::UpdateSettingsPolicy(userId);
}

void InstallLocalEnterpriseAppEnabledForAccountPlugin::OnAdminRemoveDone(int32_t userId)
{
    EDMLOGI("InstallLocalEnterpriseAppEnabledForAccountPlugin OnAdminRemoveDone...");
    InstallLocalEnterpriseAppPolicyUtils::UpdatePolicyByUser(userId);
    InstallLocalEnterpriseAppPolicyUtils::UpdateSettingsPolicy(userId);
}

void InstallLocalEnterpriseAppEnabledForAccountPlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    EDMLOGI("InstallLocalEnterpriseAppEnabledForAccountPlugin OnOtherServiceStart...");
    std::vector<int32_t> userIds;
    IPolicyManager::GetInstance()->GetPolicyUserIds(userIds);
    for (int32_t userId : userIds) {
        InstallLocalEnterpriseAppPolicyUtils::UpdatePolicyByUser(userId);
        InstallLocalEnterpriseAppPolicyUtils::UpdateSettingsPolicy(userId);
    }
}
} // namespace EDM
} // namespace OHOS
