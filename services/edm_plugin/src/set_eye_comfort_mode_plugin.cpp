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

#include "set_eye_comfort_mode_plugin.h"

#include "battery_utils.h"
#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "edm_os_account_manager_impl.h"
#include "iplugin_manager.h"
#include "string_serializer.h"

namespace OHOS {
namespace EDM {

const std::string KEY_EYE_COMFORT_MODE = "settings.display.eye_comfort_mode";
const std::string SETTINGS_DATA_BASE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_";
const std::string SETTINGS_DATA_PREFIX = "?Proxy=true";
const std::string KEY_EYE_COMFORT_ON = "on";
const std::string KEY_EYE_COMFORT_OFF = "off";
const std::string KEY_EYE_COMFORT_UNKNOWN = "unknown";

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetEyeComfortModePlugin::GetPlugin());

void SetEyeComfortModePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SetEyeComfortModePlugin, std::string>> ptr)
{
    EDMLOGD("SetEyeComfortModePlugin InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS);
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(typePermissions,
        IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::SET_EYE_COMFORT_MODE, PolicyName::POLICY_SET_EYE_COMFORT_MODE,
        config, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetEyeComfortModePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode SetEyeComfortModePlugin::OnSetPolicy(std::string &data)
{
    EDMLOGD("SetEyeComfortModePlugin start set set eyeComfort data = %{public}s.", data.c_str());
    if (data == KEY_EYE_COMFORT_ON || data == KEY_EYE_COMFORT_OFF) {
        int32_t value = EdmConstants::DeviceInfo::EYE_COMFORT_OFF;
        if (data == KEY_EYE_COMFORT_ON) {
            value = EdmConstants::DeviceInfo::EYE_COMFORT_ON;
        }
        std::vector<int32_t> ids;
        std::string userId;
        ErrCode code = std::make_shared<EdmOsAccountManagerImpl>()->QueryActiveOsAccountIds(ids);
        if (SUCCEEDED(code) && !ids.empty()) {
            userId = std::to_string(ids.at(0));
        } else {
            EDMLOGE("SetEyeComfortModePlugin::get current account id failed : %{public}d.", code);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        std::string uri = SETTINGS_DATA_BASE_URI + userId + SETTINGS_DATA_PREFIX;
        code = EdmDataAbilityUtils::UpdateSettingsData(uri, KEY_EYE_COMFORT_MODE, std::to_string(value));
        if (FAILED(code)) {
            EDMLOGE("SetEyeComfortModePlugin::set eyecomfort failed : %{public}d.", code);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        return ERR_OK;
    }
    return EdmReturnErrCode::PARAM_ERROR;
}

ErrCode SetEyeComfortModePlugin::OnGetPolicy(std::string &value, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGD("SetEyeComfortModePlugin OnGetPolicy");
    int32_t result = 0;
    std::vector<int32_t> ids;
    std::string currentId;
    ErrCode code = std::make_shared<EdmOsAccountManagerImpl>()->QueryActiveOsAccountIds(ids);
    if (SUCCEEDED(code) && !ids.empty()) {
        currentId = std::to_string(ids.at(0));
    } else {
        EDMLOGE("SetEyeComfortModePlugin::get current account id failed : %{public}d.", code);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string uri = SETTINGS_DATA_BASE_URI + currentId + SETTINGS_DATA_PREFIX;
    code = EdmDataAbilityUtils::GetIntFromSettingsDataShare(uri, KEY_EYE_COMFORT_MODE, result);
    if (code != ERR_OK) {
        EDMLOGE("SetEyeComfortModePlugin::get data from database failed : %{public}d.", code);
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string retValue = KEY_EYE_COMFORT_UNKNOWN;
    if (result == EdmConstants::DeviceInfo::EYE_COMFORT_ON) {
        retValue = KEY_EYE_COMFORT_ON;
    } else if (result == EdmConstants::DeviceInfo::EYE_COMFORT_OFF) {
        retValue = KEY_EYE_COMFORT_OFF;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteString(retValue);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
