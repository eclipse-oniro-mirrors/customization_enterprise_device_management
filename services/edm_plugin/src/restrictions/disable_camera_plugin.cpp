/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "disable_camera_plugin.h"


#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"
#include "privacy_kit.h"

namespace OHOS {
namespace EDM {
const std::string permissionName = "ohos.permission.CAMERA";
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisableCameraPlugin>());

DisableCameraPlugin::DisableCameraPlugin()
{
    EDMLOGI("DisableCameraPlugin InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    typePermissions.emplace(IPlugin::PermissionType::BYOD_DEVICE_ADMIN,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    policyCode_ = EdmInterfaceCode::DISABLE_CAMERA;
    policyName_ = PolicyName::POLICY_DISABLE_CAMERA;
    persistParam_ = "persist.edm.camera_disable";
}

ErrCode DisableCameraPlugin::CheckConflictPolicy(int32_t userId)
{
    // 新版验收标准（camera.txt）取消 9200010 冲突上报：设备级启用不再检测用户级禁用，
    // 设备级/用户级从严由策略合并层静默保证（用户级禁用策略保留期间，摄像头对该用户维持禁用）。
    // 因此本插件无冲突上报场景，该钩子按框架形态实现并返回 ERR_OK。
    return ERR_OK;
}

ErrCode DisableCameraPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisableCameraPlugin OnSetPolicy %{public}d", data);
    int32_t ret = OHOS::Security::AccessToken::PrivacyKit::SetDisablePolicy(permissionName, data);
    if (ret == ERR_OK) {
        EDMLOGI("DisableCameraPlugin SetOtherModulePolicy SetDisablePolicy success, %{public}d", ret);
        return ERR_OK;
    }
    EDMLOGE("DisableCameraPlugin SetOtherModulePolicy SetDisablePolicy failed, %{public}d", ret);
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}
} // namespace EDM
} // namespace OHOS
