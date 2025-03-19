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

#include "screen_off_time_plugin.h"

#include "battery_utils.h"
#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "int_serializer.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
static constexpr int32_t SCREEN_OFF_TIME_MIN_VALUE = 15000;
static constexpr int32_t SCREEN_OFF_TIME_NEVER_VALUE = -1;

const std::string KEY_SCREEN_OFF_TIME = "settings.display.screen_off_timeout";
const std::string KEY_AC_SCREEN_OFF_TIME = "settings.display.ac.screen_off_timeout";
const std::string KEY_DC_SCREEN_OFF_TIME = "settings.display.dc.screen_off_timeout";

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(ScreenOffTimePlugin::GetPlugin());

void ScreenOffTimePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<ScreenOffTimePlugin, int32_t>> ptr)
{
    EDMLOGI("ScreenOffTimePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::SCREEN_OFF_TIME, PolicyName::POLICY_SCREEN_OFF_TIME, false);
    std::map<std::string, std::map<IPlugin::PermissionType, std::string>> tagPermissionsForSet;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag11ForSet;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag12ForSet;
    typePermissionsForTag11ForSet.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_SET_SCREEN_OFF_TIME);
    typePermissionsForTag12ForSet.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS);
    tagPermissionsForSet.emplace(EdmConstants::PERMISSION_TAG_VERSION_11, typePermissionsForTag11ForSet);
    tagPermissionsForSet.emplace(EdmConstants::PERMISSION_TAG_VERSION_12, typePermissionsForTag12ForSet);
    IPlugin::PolicyPermissionConfig setConfig = IPlugin::PolicyPermissionConfig(tagPermissionsForSet,
        IPlugin::ApiType::PUBLIC);
    ptr->InitPermission(FuncOperateType::SET, setConfig);

    std::map<std::string, std::map<IPlugin::PermissionType, std::string>> tagPermissionsForGet;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag11ForGet;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag12ForGet;
    typePermissionsForTag11ForGet.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_GET_SETTINGS);
    typePermissionsForTag12ForGet.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS);
    tagPermissionsForGet.emplace(EdmConstants::PERMISSION_TAG_VERSION_11, typePermissionsForTag11ForGet);
    tagPermissionsForGet.emplace(EdmConstants::PERMISSION_TAG_VERSION_12, typePermissionsForTag12ForGet);
    IPlugin::PolicyPermissionConfig getConfig = IPlugin::PolicyPermissionConfig(tagPermissionsForGet,
        IPlugin::ApiType::PUBLIC);
    ptr->InitPermission(FuncOperateType::GET, getConfig);
    ptr->SetSerializer(IntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&ScreenOffTimePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode ScreenOffTimePlugin::OnSetPolicy(int32_t &data)
{
    EDMLOGD("ScreenOffTimePlugin start set screen off time value = %{public}d.", data);
    if (data >= SCREEN_OFF_TIME_MIN_VALUE || data == SCREEN_OFF_TIME_NEVER_VALUE) {
#ifdef FEATURE_CHARGING_TYPE_SETTING
        if (FAILED(EdmDataAbilityUtils::UpdateSettingsData(
            BatteryUtils::GetSubUserTableUri(), KEY_AC_SCREEN_OFF_TIME, std::to_string(data)))) {
            EDMLOGE("ScreenOffTimePlugin::set ac screen off time failed");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        if (FAILED(EdmDataAbilityUtils::UpdateSettingsData(
            BatteryUtils::GetSubUserTableUri(), KEY_DC_SCREEN_OFF_TIME, std::to_string(data)))) {
            EDMLOGE("ScreenOffTimePlugin::set dc screen off time failed");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
#else
        ErrCode code = EdmDataAbilityUtils::UpdateSettingsData(KEY_SCREEN_OFF_TIME, std::to_string(data));
        if (FAILED(code)) {
            EDMLOGE("ScreenOffTimePlugin::set screen off time failed : %{public}d.", code);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
#endif
        return ERR_OK;
    }
    return EdmReturnErrCode::PARAM_ERROR;
}

ErrCode ScreenOffTimePlugin::OnGetPolicy(std::string &value, MessageParcel &data, MessageParcel &reply, int32_t userId)
{
    EDMLOGI("ScreenOffTimePlugin OnGetPolicy");
    int32_t result = 0;
    ErrCode code;
#ifdef FEATURE_CHARGING_TYPE_SETTING
    std::string newKey;
    if (BatteryUtils::GetBatteryPluggedType() == BatteryUtils::PLUGGED_TYPE_AC) {
        newKey = KEY_AC_SCREEN_OFF_TIME;
    } else {
        newKey = KEY_DC_SCREEN_OFF_TIME;
    }
    code = EdmDataAbilityUtils::GetIntFromSettingsDataShare(BatteryUtils::GetSubUserTableUri(), newKey, result);
#else
    code = EdmDataAbilityUtils::GetIntFromSettingsDataShare(KEY_SCREEN_OFF_TIME, result);
#endif
    if (code != ERR_OK) {
        EDMLOGE("ScreenOffTimePlugin::get screen off time from database failed : %{public}d.", code);
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(result);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
