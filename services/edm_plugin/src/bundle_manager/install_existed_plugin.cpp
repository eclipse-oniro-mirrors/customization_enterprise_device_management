/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "install_existed_plugin.h"

#include <algorithm>
#include <system_ability_definition.h>

#include "app_control/app_control_proxy.h"
#include "bundle_installer_interface.h"
#include "edm_constants.h"
#include "edm_sys_manager.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<InstallExistedPlugin>());
constexpr int32_t ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST = 8521220;
constexpr int32_t ERR_BUNDLE_MANAGER_INVALID_USER_ID = 8521219;
constexpr int32_t ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_INSTALL = 8520965;

InstallExistedPlugin::InstallExistedPlugin()
{
    EDMLOGI("InstallExistedPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::INSTALL_EXISTED;
    policyName_ = PolicyName::POLICY_INSTALL_EXISTED;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_INSTALL_BUNDLE, IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode InstallExistedPlugin::OnHandlePolicy(std::uint32_t func_code, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    std::string bundleName = data.ReadString();
    EDMLOGI("InstallExistedPlugin OnHandlePolicy bundleName : %{public}s, userId : %{public}d",
            bundleName.c_str(), userId);
    if (bundleName.empty() || userId < 0) {
        EDMLOGE("InstallExistedPlugin: invalid bundleName or userId");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    sptr<AppExecFwk::IBundleInstaller> iBundleInstaller = nullptr;
    ErrCode ret = GetBundleInstaller(iBundleInstaller);
    if (ret != ERR_OK) {
        return ret;
    }
    ret = iBundleInstaller->InstallExisted(bundleName, userId);
    switch (ret) {
        case ERR_OK:
            return ERR_OK;
        case ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST:
            return EdmReturnErrCode::DOCK_APP_NOT_INSTALLED;
        case ERR_BUNDLE_MANAGER_APP_CONTROL_DISALLOWED_INSTALL:
            return EdmReturnErrCode::INSTALL_APP_ENTERPRISE_DISALLOWED;
        case ERR_BUNDLE_MANAGER_INVALID_USER_ID:
            return EdmReturnErrCode::UID_INVALID;
        default:
            break;
    }
    EDMLOGI("InstallExistedPlugin: InstallExisted failed, bundleName=%{public}s, ret=%{public}d",
        bundleName.c_str(), ret);
    return EdmReturnErrCode::APPLICATION_INSTALL_FAILED;
}

ErrCode InstallExistedPlugin::GetBundleInstaller(sptr<AppExecFwk::IBundleInstaller> &iBundleInstaller)
{
    auto remoteObject = EdmSysManager::GetRemoteObjectOfSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    auto iBundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        EDMLOGE("InstallExistedPlugin: failed to get iBundleMgr");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    iBundleInstaller = iBundleMgr->GetBundleInstaller();
    if (iBundleInstaller == nullptr || iBundleInstaller->AsObject() == nullptr) {
        EDMLOGE("InstallExistedPlugin: failed to get iBundleInstaller");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
