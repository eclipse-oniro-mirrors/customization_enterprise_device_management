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

#include "disallowed_p2p_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "inner_api/wifi_p2p.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisallowedP2PPlugin>());

DisallowedP2PPlugin::DisallowedP2PPlugin()
{
    EDMLOGI("DisallowedP2PPlugin InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    typePermissions.emplace(IPlugin::PermissionType::BYOD_DEVICE_ADMIN,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    policyCode_ = EdmInterfaceCode::DISALLOWED_P2P;
    policyName_ = PolicyName::POLICY_DISALLOWED_P2P;
}

ErrCode DisallowedP2PPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisallowedP2PPlugin SetOtherModulePolicy");
    if (!system::SetParameter("persist.edm.p2p_disallowed", data ? "true" : "false")) {
        EDMLOGE("BasicBoolPlugin set param failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    auto p2p = Wifi::WifiP2p::GetInstance(WIFI_P2P_ABILITY_ID);
    if (p2p == nullptr) {
        EDMLOGE("DisallowedTetheringPlugin SetOtherModulePolicy WifiP2p nullptr");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (data) {
        p2p->RemoveGroup();
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
