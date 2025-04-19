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

#include "disallowed_wifi_list_plugin.h"

#include <algorithm>

#include "system_ability_definition.h"

#include "array_wifi_id_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_sys_manager.h"
#include "edm_utils.h"
#include "iplugin_manager.h"
#include "wifi_policy_utils.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowWifiListPlugin::GetPlugin());

void DisallowWifiListPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowWifiListPlugin, std::vector<WifiId>>> ptr)
{
    EDMLOGI("DisallowWifiListPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_WIFI_LIST, PolicyName::POLICY_DISALLOWED_WIFI_LIST,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayWifiIdSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowWifiListPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&DisallowWifiListPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&DisallowWifiListPlugin::OnAdminRemove);
}

ErrCode DisallowWifiListPlugin::OnSetPolicy(std::vector<WifiId> &data,
    std::vector<WifiId> &currentData, std::vector<WifiId> &mergeData, int32_t userId)
{
    EDMLOGI("DisallowWifiListPlugin OnSetPolicy userId = %{public}d", userId);
    return WifiPolicyUtils::AddWifiListPolicy(data, currentData, mergeData, userId, false);
}

ErrCode DisallowWifiListPlugin::OnRemovePolicy(std::vector<WifiId> &data, std::vector<WifiId> &currentData,
    std::vector<WifiId> &mergeData, int32_t userId)
{
    EDMLOGI("DisallowWifiListPlugin OnRemovePolicy userId : %{public}d:", userId);
    return WifiPolicyUtils::RemoveWifiListPolicy(data, currentData, mergeData, userId, false);
}

ErrCode DisallowWifiListPlugin::OnAdminRemove(const std::string &adminName, std::vector<WifiId> &data,
    std::vector<WifiId> &mergeData, int32_t userId)
{
    EDMLOGI("DisallowWifiListPlugin OnAdminRemove");
    if (data.empty()) {
        EDMLOGW("DisallowWifiListPlugin OnRemovePolicy data is empty:");
        return ERR_OK;
    }
    return WifiPolicyUtils::SetWifiAccessList(mergeData, false);
}
} // namespace EDM
} // namespace OHOS
