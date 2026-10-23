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

#include "disallow_notification_center_plugin.h"

#include <cstdlib>

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const std::string PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE = "persist.edm.control_notification_center_disable";
constexpr int32_t NOTIFICATION_CENTER_DISABLE_BIT = 0x02;

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<DisallowNotificationCenterPlugin>());

DisallowNotificationCenterPlugin::DisallowNotificationCenterPlugin()
{
    EDMLOGI("DisallowNotificationCenterPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOW_NOTIFICATION_CENTER;
    policyName_ = PolicyName::POLICY_DISALLOW_NOTIFICATION_CENTER;
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
}

ErrCode DisallowNotificationCenterPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisallowNotificationCenterPlugin SetOtherModulePolicy data : %{public}d", data);
    int32_t value = atoi(system::GetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, "0").c_str());
    value = data ? (value | NOTIFICATION_CENTER_DISABLE_BIT) : (value & ~NOTIFICATION_CENTER_DISABLE_BIT);
    if (!system::SetParameter(PARAM_CONTROL_NOTIFICATION_CENTER_DISABLE, std::to_string(value))) {
        EDMLOGE("DisallowNotificationCenterPlugin set param failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode DisallowNotificationCenterPlugin::OnAdminRemove(const std::string &adminName, bool &data, bool &mergeData,
    int32_t userId)
{
    EDMLOGI("DisallowNotificationCenterPlugin OnAdminRemove adminName : %{public}s, data : %{public}d",
        adminName.c_str(), data);
    if (!mergeData && data) {
        ErrCode ret = SetOtherModulePolicy(false, userId);
        if (FAILED(ret)) {
            return ret;
        }
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS