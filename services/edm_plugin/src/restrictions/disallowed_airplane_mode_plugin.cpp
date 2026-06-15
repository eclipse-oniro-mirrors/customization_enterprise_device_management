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

#include "disallowed_airplane_mode_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "net_conn_client.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisallowedAirplaneModePlugin>());

DisallowedAirplaneModePlugin::DisallowedAirplaneModePlugin()
{
    EDMLOGI("DisallowedAirplaneModePlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOWED_AIRPLANE_MODE;
    policyName_ = PolicyName::POLICY_DISALLOWED_AIRPLANE_MODE;
    std::map<std::string, std::map<IPlugin::PermissionType, std::string>> tagPermissions;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag11;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag26;
    typePermissionsForTag11.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_NETWORK);
    typePermissionsForTag26.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_11, typePermissionsForTag11);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_26, typePermissionsForTag26);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(tagPermissions, IPlugin::ApiType::PUBLIC);
    persistParam_ = "persist.edm.airplane_mode_disable";
}

ErrCode DisallowedAirplaneModePlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisallowedAirplaneModePlugin OnSetPolicy disallow = %{public}d", data);
    if (data) {
        int32_t ret = NetManagerStandard::NetConnClient::GetInstance().SetAirplaneMode(false);
        EDMLOGI("DisallowedAirplaneModePlugin OnSetPolicy SetAirplaneMode = %{public}d", ret);
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
