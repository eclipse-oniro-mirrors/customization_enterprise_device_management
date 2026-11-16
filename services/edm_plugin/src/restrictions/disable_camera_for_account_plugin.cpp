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

#include "disable_camera_for_account_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "privacy_kit.h"

namespace OHOS {
namespace EDM {
// 设备级摄像头禁用使用的权限名（DisableCameraPlugin 同款），用户级与设备级共用同一接口，
// 以 userId 参数区分层级：-1 设备级（DisableCameraPlugin 缺省形式）、>=0 用户级（本插件）
const std::string permissionName = "ohos.permission.CAMERA";

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<DisableCameraForAccountPlugin>());

DisableCameraForAccountPlugin::DisableCameraForAccountPlugin()
{
    EDMLOGI("DisableCameraForAccountPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOWED_CAMERA_FOR_ACCOUNT;
    policyName_ = PolicyName::POLICY_DISABLED_CAMERA_FOR_ACCOUNT;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode DisableCameraForAccountPlugin::CheckConflictPolicy(int32_t userId)
{
    // 新版验收标准（camera.txt）取消 9200010 冲突上报：设备级/用户级/多 MDM 采用从严规则，
    // "有一个设置为禁止则摄像头被禁用"由策略合并层静默保证——其他 admin 或设备级禁用期间，
    // 本 admin 设置启用时 mergePolicy 分支保持策略不生效，摄像头维持禁用。
    // 因此本插件无冲突上报场景，该钩子按框架形态实现并返回 ERR_OK。
    return ERR_OK;
}

ErrCode DisableCameraForAccountPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisableCameraForAccountPlugin::SetOtherModulePolicy, policy: %{public}d, userId: %{public}d",
        data, userId);
    if (userId < 0) {
        EDMLOGE("DisableCameraForAccountPlugin::SetOtherModulePolicy invalid userId: %{public}d", userId);
        return EdmReturnErrCode::UID_INVALID;
    }
    // 调用安全基础平台（access_token privacy）用户级摄像头禁用接口，与设备级
    // DisableCameraPlugin 为同族接口，以 userId 区分层级（-1 设备级、>=0 用户级）。
    // 管控范围：系统相机、三方相机、内置摄像头、外置摄像头、东湖相机、光感无界主题。
    // 注：camera_framework 消费侧当前仅按设备级（userId=-1）查询，用户级生效需
    // 多媒体仓配套改造（AllowOpenByOHSide 按调用者所属 userId 查询 3 参）。
    ErrCode ret = OHOS::Security::AccessToken::PrivacyKit::SetDisablePolicy(permissionName, data, userId);
    if (FAILED(ret)) {
        EDMLOGE("DisableCameraForAccountPlugin::SetOtherModulePolicy SetDisablePolicy ret: %{public}d, "
            "userId: %{public}d", ret, userId);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
