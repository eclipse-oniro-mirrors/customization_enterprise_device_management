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

#include "set_floating_navigation_plugin.h"

#include "battery_utils.h"
#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "edm_os_account_manager_impl.h"
#include "iplugin_manager.h"
#include "string_serializer.h"

namespace OHOS {
namespace EDM {

const std::string KEY_EYE_COMFORT_MODE = "floatingNavigation";
const std::string SETTINGS_DATA_BASE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_";
const std::string SETTINGS_DATA_PREFIX = "?Proxy=true";

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetFloatingNavigationPlugin::GetPlugin());

void SetFloatingNavigationPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SetFloatingNavigationPlugin,
    std::string>> ptr)
{
    EDMLOGD("SetFloatingNavigationPlugin InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS);
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(typePermissions,
        IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::SET_FLOATING_NAVIGATION, PolicyName::POLICY_SET_FLOATING_NAVIGATION,
        config, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetFloatingNavigationPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode SetFloatingNavigationPlugin::OnSetPolicy(std::string &data, std::string &currentData, std::string &mergeData,
    int32_t userId)
{
    EDMLOGD("SetFloatingNavigationPlugin start set floating nagivation data = %{public}s.", data.c_str());
    if (data.empty()) {
        EDMLOGE("OnSetPolicy floating nagivation is empty.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
        
    std::string uri = SETTINGS_DATA_BASE_URI + std::to_string(userId) + SETTINGS_DATA_PREFIX;
    ErrCode code = EdmDataAbilityUtils::UpdateSettingsData(uri, KEY_EYE_COMFORT_MODE, data);
    if (FAILED(code)) {
        EDMLOGE("SetFloatingNavigationPlugin::set eyecomfort failed : %{public}d.", code);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode SetFloatingNavigationPlugin::OnGetPolicy(std::string &value, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGD("SetFloatingNavigationPlugin OnGetPolicy");
    std::string result;
    std::string uri = SETTINGS_DATA_BASE_URI + std::to_string(userId) + SETTINGS_DATA_PREFIX;
    ErrCode code = EdmDataAbilityUtils::GetStringFromSettingsDataShare(uri, KEY_EYE_COMFORT_MODE, result);
    if (code != ERR_OK) {
        EDMLOGE("SetFloatingNavigationPlugin::get data from database failed : %{public}d.", code);
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteString(result);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS