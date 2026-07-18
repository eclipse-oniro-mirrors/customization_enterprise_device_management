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

#include "parameters.h"

#include "edm_ipc_interface_code.h"
#include "edm_constants.h"
#include "iplugin_manager.h"
#include "install_local_enterprise_app_policy_utils.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<InstallLocalEnterpriseAppEnabledPlugin>());
const char *PERSIST_LOCAL_INSTALL_ENABLE = "persist.edm.is_local_install_enable";

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

ErrCode InstallLocalEnterpriseAppEnabledPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
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

ErrCode InstallLocalEnterpriseAppEnabledPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("InstallLocalEnterpriseAppEnabledPlugin SetOtherModulePolicy data = %{public}d", data);
    if (!system::SetParameter(PERSIST_LOCAL_INSTALL_ENABLE, data ? EdmConstants::CONST_TRUE :
        EdmConstants::CONST_FALSE)) {
        EDMLOGE("InstallLocalEnterpriseAppEnabledPlugin set param failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode ret = InstallLocalEnterpriseAppPolicyUtils::SetSettingsDataAndUserPolicy(data ?
        InstallLocalEnterpriseAppPolicyUtils::POLICY_FORCE_ENABLE :
        InstallLocalEnterpriseAppPolicyUtils::POLICY_FORCE_DISABLE);
    if (FAILED(ret)) {
        EDMLOGE("InstallLocalEnterpriseAppEnabledPlugin SetSettingsDataAndUserPolicy failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode InstallLocalEnterpriseAppEnabledPlugin::OnAdminRemove(const std::string &adminName, bool &data,
    bool &mergeData, int32_t userId)
{
    EDMLOGI("InstallLocalEnterpriseAppEnabledPlugin OnAdminRemove adminName: %{public}s, data : %{public}d",
        adminName.c_str(), data);
    if (!mergeData && data && !system::SetParameter(PERSIST_LOCAL_INSTALL_ENABLE, EdmConstants::CONST_FALSE)) {
        EDMLOGE("InstallLocalEnterpriseAppEnabledPlugin set param failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t policy = InstallLocalEnterpriseAppPolicyUtils::POLICY_NO_CONTROLL;
    ErrCode ret = InstallLocalEnterpriseAppPolicyUtils::SetSettingsDataAndUserPolicy(policy);
    if (FAILED(ret)) {
        EDMLOGE("InstallLocalEnterpriseAppEnabledPlugin SetSettingsDataAndUserPolicy failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
