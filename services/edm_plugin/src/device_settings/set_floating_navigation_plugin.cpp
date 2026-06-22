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

#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {

const std::string KEY_FLOATING_NAVIGATION = "floatingNavigation";
const std::string SETTINGS_DATA_BASE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_";
const std::string SETTINGS_DATA_PREFIX = "?Proxy=true";

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<SetFloatingNavigationPlugin>());

SetFloatingNavigationPlugin::SetFloatingNavigationPlugin()
{
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS);
    policyCode_ = EdmInterfaceCode::SET_FLOATING_NAVIGATION;
    policyName_ = PolicyName::POLICY_SET_FLOATING_NAVIGATION;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode SetFloatingNavigationPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    std::string handleData = data.ReadString();
    EDMLOGD("SetFloatingNavigationPlugin start set floating nagivation data = %{public}s.", handleData.c_str());
    if (handleData.empty()) {
        EDMLOGE("OnHandlePolicy floating nagivation is empty.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    if ((handleData != "0") && (handleData != "1")) {
        EDMLOGE("OnHandlePolicy floating nagivation is error.");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
        
    std::string uri = SETTINGS_DATA_BASE_URI + std::to_string(userId) + SETTINGS_DATA_PREFIX;
    ErrCode code = EdmDataAbilityUtils::UpdateSettingsData(uri, KEY_FLOATING_NAVIGATION, handleData);
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
    ErrCode code = EdmDataAbilityUtils::GetStringFromSettingsDataShare(uri, KEY_FLOATING_NAVIGATION, result);
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
