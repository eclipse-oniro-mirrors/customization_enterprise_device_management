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

ErrCode InstallLocalEnterpriseAppEnabledForAccountPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    bool handelData = data.ReadBool();
    bool currentData = policyData.policyData == EdmConstants::CONST_TRUE;
    bool mergeData = policyData.mergePolicyData == EdmConstants::CONST_TRUE;
    ErrCode result = OnSetPolicy(handelData, currentData, mergeData, userId);
    if (result != ERR_OK) {
        return result;
    }
    std::string afterHandle = currentData ? EdmConstants::CONST_TRUE : EdmConstants::CONST_FALSE;
    std::string afterMerge = mergeData ? EdmConstants::CONST_TRUE : EdmConstants::CONST_FALSE;
    policyData.isChanged = (policyData.policyData != afterHandle);
    policyData.policyData = afterHandle;
    policyData.mergePolicyData = afterMerge;
    return ERR_OK;
}

ErrCode InstallLocalEnterpriseAppEnabledForAccountPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("InstallLocalEnterpriseAppEnabledForAccountPlugin SetOtherModulePolicy data = %{public}d", data);
    ErrCode ret = InstallLocalEnterpriseAppPolicyUtils::SetEnterpriseUserPolicy(data, userId);
    if (FAILED(ret)) {
        EDMLOGE("InstallLocalEnterpriseAppEnabledForAccountPlugin SetSpecificOsAccountConstraints failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    ret = InstallLocalEnterpriseAppPolicyUtils::SetSettingsDataAndUserPolicy(data ?
        InstallLocalEnterpriseAppPolicyUtils::POLICY_FORCE_ENABLE :
        InstallLocalEnterpriseAppPolicyUtils::POLICY_FORCE_DISABLE, userId);
    if (FAILED(ret)) {
        EDMLOGE("InstallLocalEnterpriseAppEnabledForAccountPlugin SetSettingsDataAndUserPolicy failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode InstallLocalEnterpriseAppEnabledForAccountPlugin::OnAdminRemove(const std::string &adminName,
    bool &data, bool &mergeData, int32_t userId)
{
    EDMLOGI("InstallLocalEnterpriseAppEnabledForAccountPlugin OnAdminRemove adminName: %{public}s, data : %{public}d",
        adminName.c_str(), data);
    ErrCode ret;
    if (!mergeData && data) {
        ret = InstallLocalEnterpriseAppPolicyUtils::SetEnterpriseUserPolicy(false, userId);
        if (FAILED(ret)) {
            EDMLOGE("InstallLocalEnterpriseAppEnabledForAccountPlugin SetSpecificOsAccountConstraints failed");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    ret =
        InstallLocalEnterpriseAppPolicyUtils::SetSettingsDataAndUserPolicy(InstallLocalEnterpriseAppPolicyUtils::POLICY_NO_CONTROLL, userId);
    if (FAILED(ret)) {
        EDMLOGE("InstallLocalEnterpriseAppEnabledForAccountPlugin SetSettingsDataAndUserPolicy failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
