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

#include "install_local_enterprise_app_enabled_plugin.h"

#include "edm_ipc_interface_code.h"
#include "edm_constants.h"
#include "iplugin_manager.h"
#include "install_local_enterprise_app_policy_utils.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<InstallLocalEnterpriseAppEnabledPlugin>());

InstallLocalEnterpriseAppEnabledPlugin::InstallLocalEnterpriseAppEnabledPlugin()
{
    EDMLOGI("InstallLocalEnterpriseAppEnabledPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED;
    policyName_ = PolicyName::POLICY_SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM, IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
    persistParam_ = "persist.edm.is_local_install_enable";
}

void InstallLocalEnterpriseAppEnabledPlugin::OnHandlePolicyDone(
    bool data, bool isGlobalChanged, int32_t userId)
{
    EDMLOGI("InstallLocalEnterpriseAppEnabledPlugin OnHandlePolicyDone...");
    if (!isGlobalChanged) {
        return;
    }
    InstallLocalEnterpriseAppPolicyUtils::UpdatePolicyByUser();
    InstallLocalEnterpriseAppPolicyUtils::UpdateSettingsPolicy();
}

void InstallLocalEnterpriseAppEnabledPlugin::OnAdminRemoveDone(int32_t userId)
{
    EDMLOGI("InstallLocalEnterpriseAppEnabledPlugin OnAdminRemoveDone...");
    InstallLocalEnterpriseAppPolicyUtils::UpdatePolicyByUser();
    InstallLocalEnterpriseAppPolicyUtils::UpdateSettingsPolicy();
    
}

void InstallLocalEnterpriseAppEnabledPlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    EDMLOGI("InstallLocalEnterpriseAppEnabledPlugin OnOtherServiceStart...");
    InstallLocalEnterpriseAppPolicyUtils::UpdatePolicyByUser();
    InstallLocalEnterpriseAppPolicyUtils::UpdateSettingsPolicy();
}
} // namespace EDM
} // namespace OHOS
