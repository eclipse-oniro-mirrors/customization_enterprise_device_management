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

#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#ifdef WIFI_EDM_ENABLE
#include "inner_api/wifi_hotspot.h"
#endif
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowedTetheringPlugin::GetPlugin());

void DisallowedTetheringPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisallowedTetheringPlugin, bool>> ptr)
{
    EDMLOGI("DisallowedTetheringPlugin InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    typePermissions.emplace(IPlugin::PermissionType::BYOD_DEVICE_ADMIN,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_TETHERING, PolicyName::POLICY_DISALLOWED_TETHERING, config, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedTetheringPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowedTetheringPlugin::OnAdminRemove);
    persistParam_ = "persist.edm.tethering_disallowed";
}

ErrCode DisallowedTetheringPlugin::OnSetPolicy(bool &data, bool &currentData, bool &mergePolicy, int32_t userId)
{
    EDMLOGE("BasicBoolPlugin %{public}d, %{public}d, %{public}d.", data, currentData, mergePolicy);
    if (mergePolicy) {
        currentData = data;
        return ERR_OK;
    }
    if (!persistParam_.empty() && !system::SetParameter(persistParam_, data ? "true" : "false")) {
        EDMLOGE("BasicBoolPlugin set param failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode ret = SetOtherModulePolicy(data, userId);
    if (FAILED(ret)) {
        return ret;
    }
    currentData = data;
    mergePolicy = data;
    return ERR_OK;
}

ErrCode DisallowedTetheringPlugin::OnAdminRemove(const std::string &adminName,
    bool &data, bool &mergeData, int32_t userId)
{
    EDMLOGI("BasicBoolPlugin OnAdminRemove adminName : %{public}s, data : %{public}d", adminName.c_str(), data);
    if (!mergeData && data) {
        if (!persistParam_.empty() && !system::SetParameter(persistParam_, "false")) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        ErrCode ret = SetOtherModulePolicy(false, userId);
        if (FAILED(ret)) {
            return ret;
        }
    }
    return ERR_OK;
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
