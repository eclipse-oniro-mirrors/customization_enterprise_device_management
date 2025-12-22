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

#include "set_device_name_plugin.h"

#include "battery_utils.h"
#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "edm_os_account_manager_impl.h"
#include "iplugin_manager.h"
#include "string_serializer.h"

namespace OHOS {
namespace EDM {
const std::string KEY_USER_DEFINED_DEVICE_NAME = "settings.general.user_defined_device_name";
const std::string KEY_DISPLAY_DEVICE_NAME = "settings.general.display_device_name";
const std::string SETTINGS_DATA_BASE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE_";
const std::string SETTINGS_DATA_PREFIX = "?Proxy=true";
const int32_t DEVICE_NAME_MAX_LENGTH = 30;


const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetDeviceNamePlugin::GetPlugin());

void SetDeviceNamePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SetDeviceNamePlugin, std::string>> ptr)
{
    EDMLOGD("SetDeviceNamePlugin::InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS);
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(typePermissions,
        IPlugin::ApiType::PUBLIC);

    ptr->InitAttribute(EdmInterfaceCode::SET_DEVICE_NAME, PolicyName::POLICY_SET_DEVICE_NAME, config, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetDeviceNamePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode SetDeviceNamePlugin::OnSetPolicy(std::string &data, std::string &currentData, std::string &mergeData,
    int32_t userId)
{
    EDMLOGI("SetDeviceNamePlugin start set set deviceName data = %{public}s.", data.c_str());
    if (!data.empty() && data.length() <= DEVICE_NAME_MAX_LENGTH) {
        std::string uri = SETTINGS_DATA_BASE_URI + std::to_string(userId) + SETTINGS_DATA_PREFIX;
        ErrCode code1 = EdmDataAbilityUtils::UpdateSettingsData(uri, KEY_USER_DEFINED_DEVICE_NAME, data);
        ErrCode code2 = EdmDataAbilityUtils::UpdateSettingsData(uri, KEY_DISPLAY_DEVICE_NAME, data);
        if (FAILED(code1) || FAILED(code2)) {
            EDMLOGE("SetDeviceNamePlugin::set deviceName failed, code1: %{public}d, code2: %{public}d.",
                code1, code2);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    } else {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    return ERR_OK;
}

ErrCode SetDeviceNamePlugin::OnGetPolicy(std::string &value, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGD("SetDeviceNamePlugin::OnGetPolicy");
    std::string result;
    std::string uri = SETTINGS_DATA_BASE_URI + std::to_string(userId) + SETTINGS_DATA_PREFIX;
    ErrCode code = EdmDataAbilityUtils::GetStringFromSettingsDataShare(uri, KEY_DISPLAY_DEVICE_NAME, result);
    if (code != ERR_OK) {
        EDMLOGE("SetDeviceNamePlugin::get data from database failed : %{public}d.", code);
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    reply.WriteInt32(ERR_OK);
    reply.WriteString(result);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
