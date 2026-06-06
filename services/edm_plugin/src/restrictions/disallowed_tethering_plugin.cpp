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

#include "disallowed_tethering_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#ifdef WIFI_EDM_ENABLE
#include "inner_api/wifi_hotspot.h"
#endif
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisallowedTetheringPlugin>());

DisallowedTetheringPlugin::DisallowedTetheringPlugin()
{
    EDMLOGI("DisallowedTetheringPlugin InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    typePermissions.emplace(IPlugin::PermissionType::BYOD_DEVICE_ADMIN,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    policyCode_ = EdmInterfaceCode::DISALLOWED_TETHERING;
    policyName_ = PolicyName::POLICY_DISALLOWED_TETHERING;
    persistParam_ = "persist.edm.tethering_disallowed";
}

ErrCode DisallowedTetheringPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
#ifdef WIFI_EDM_ENABLE
    EDMLOGI("DisallowedTetheringPlugin SetOtherModulePolicy");
    auto hotspot = Wifi::WifiHotspot::GetInstance(WIFI_HOTSPOT_ABILITY_ID);
    if (hotspot == nullptr) {
        EDMLOGE("DisallowedTetheringPlugin SetOtherModulePolicy WifiHotspot nullptr");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = ERR_OK;
    if (data) {
        ret = hotspot->DisableHotspot();
    }
    if (ret != ERR_OK) {
        EDMLOGE("DisallowedTetheringPlugin SetOtherModulePolicy DisableHotspot error.%{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
#endif
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
