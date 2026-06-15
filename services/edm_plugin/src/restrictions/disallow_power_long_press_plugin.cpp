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

#include "disallow_power_long_press_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "edm_sys_manager.h"
#include "edm_data_ability_utils.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisallowPowerLongPressPlugin>());

DisallowPowerLongPressPlugin::DisallowPowerLongPressPlugin()
{
    EDMLOGI("DisallowPowerLongPressPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOW_POWER_LONG_PRESS;
    policyName_ = PolicyName::POLICY_DISALLOW_POWER_LONG_PRESS;
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(typePermissions,
        IPlugin::ApiType::PUBLIC);
    persistParam_ = "persist.edm.disable_power_key_shutdown";
}

ErrCode DisallowPowerLongPressPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisallowPowerLongPressPlugin SetOtherModulePolicy...");
    return EdmDataAbilityUtils::UpdateSettingsData("settings.power.block_long_press", data ? "1" : "0");
}
} // namespace EDM
} // namespace OHOS