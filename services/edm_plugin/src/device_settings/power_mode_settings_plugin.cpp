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

#include "power_mode_settings_plugin.h"

#include <cerrno>
#include <climits>
#include <cstdlib>
#include <string>

#include "battery_utils.h"
#include "edm_constants.h"
#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "edm_json_builder.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "iextra_policy_notification.h"
#include "iplugin_manager.h"
#include "override_interface_name.h"
#include "setting_item_policy.h"

namespace OHOS {
namespace EDM {
static constexpr int32_t SCREEN_OFF_TIME_MIN_VALUE = 15000;
static constexpr int32_t SCREEN_OFF_TIME_NEVER_VALUE = -1;

const std::string KEY_AC_SCREEN_OFF_TIME = "settings.display.ac.screen_off_timeout";
const std::string KEY_DC_SCREEN_OFF_TIME = "settings.display.dc.screen_off_timeout";
const std::string KEY_POWER_AC_SUSPEND = "settings.power.ac.suspend_sources";
const std::string KEY_POWER_DC_SUSPEND = "settings.power.dc.suspend_sources";
const std::string KEY_TIME_OUT = "timeout";
const char* const KEY_ACTION = "action";
const char* const KEY_DELAY_TIME = "delayMs";
const char* const KEY_POWER_SCENE = "powerScene";
const char* const KEY_POWER_POLICY = "powerPolicy";
const char* const KEY_POWER_POLICY_ACTION = "powerPolicyAction";
const char* const KEY_POWER_DELAY_TIME = "delayTime";
// Reserved sentinel value agreed with PowerMgrService: delayTime=30000 is treated as invalid
// because the power suspend framework uses it internally as a no-op/default marker.
static constexpr uint32_t INVALID_DELAY_TIME = 30000;

const bool REGISTER_POWER_MODE_SETTINGS = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<PowerModeSettingsPlugin>(EdmInterfaceCode::POWER_MODE_SETTINGS,
        PolicyName::POLICY_POWER_MODE_SETTINGS));

static bool ParseScreenOffTime(const std::string &valueStr, int32_t &value)
{
    if (valueStr.empty()) {
        return false;
    }
    errno = 0;
    char *end = nullptr;
    long parsed = std::strtol(valueStr.c_str(), &end, 10);
    if (errno != 0 || end == nullptr || *end != '\0' || parsed > INT32_MAX || parsed < INT32_MIN) {
        return false;
    }
    value = static_cast<int32_t>(parsed);
    return true;
}

PowerModeSettingsPlugin::PowerModeSettingsPlugin(std::uint32_t policyCode, const std::string &policyName)
{
    policyCode_ = policyCode;
    policyName_ = policyName;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

std::string PowerModeSettingsPlugin::GetScreenOffTimeKey(bool isAc) const
{
    return isAc ? KEY_AC_SCREEN_OFF_TIME : KEY_DC_SCREEN_OFF_TIME;
}

std::string PowerModeSettingsPlugin::GetSuspendKey(bool isAc) const
{
    return isAc ? KEY_POWER_AC_SUSPEND : KEY_POWER_DC_SUSPEND;
}

bool PowerModeSettingsPlugin::IsCrossUserNotAllowed(int32_t userId)
{
    int32_t currentUserId = externalManagerFactory_->CreateOsAccountManager()->GetCurrentUserId();
    if (currentUserId < 0) {
        EDMLOGW("PowerModeSettingsPlugin::IsCrossUserNotAllowed get current user failed, skip check");
        return false;
    }
    return userId != currentUserId;
}

ErrCode PowerModeSettingsPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    if (FuncCodeUtils::ConvertOperateType(typeCode) != FuncOperateType::SET) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (IS_NEW_INTERFACE(funcCode) && IsCrossUserNotAllowed(userId)) {
        EDMLOGE("PowerModeSettingsPlugin::OnHandlePolicy cross user not allowed, userId=%{public}d", userId);
        return EdmReturnErrCode::CROSS_USER_NOT_ALLOWED;
    }
    int32_t item = 0;
    if (!data.ReadInt32(item)) {
        EDMLOGE("PowerModeSettingsPlugin::OnHandlePolicy read item failed.");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return DispatchSetPolicy(item, data.ReadString());
}

ErrCode PowerModeSettingsPlugin::DispatchSetPolicy(int32_t item, const std::string &valueStr)
{
    switch (static_cast<SettingsItem>(item)) {
        case SettingsItem::SCREEN_OFF_DC:
            return SetScreenOffTime(valueStr, false);
        case SettingsItem::SCREEN_OFF_AC:
            return SetScreenOffTime(valueStr, true);
        case SettingsItem::POWER_POLICY_DC:
            return SetPowerPolicy(valueStr, false);
        case SettingsItem::POWER_POLICY_AC:
            return SetPowerPolicy(valueStr, true);
        default:
            EDMLOGE("PowerModeSettingsPlugin::DispatchSetPolicy unsupported item %{public}d", item);
            return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
}

ErrCode PowerModeSettingsPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    int32_t item = 0;
    if (!data.ReadInt32(item)) {
        EDMLOGE("PowerModeSettingsPlugin::OnGetPolicy read item failed.");
        reply.WriteInt32(EdmReturnErrCode::EXECUTE_TIME_OUT);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return DispatchGetPolicy(item, reply);
}

ErrCode PowerModeSettingsPlugin::DispatchGetPolicy(int32_t item, MessageParcel &reply)
{
    switch (static_cast<SettingsItem>(item)) {
        case SettingsItem::SCREEN_OFF_DC:
            return GetScreenOffTime(reply, false);
        case SettingsItem::SCREEN_OFF_AC:
            return GetScreenOffTime(reply, true);
        case SettingsItem::POWER_POLICY_DC:
            return GetPowerPolicy(reply, false);
        case SettingsItem::POWER_POLICY_AC:
            return GetPowerPolicy(reply, true);
        default:
            EDMLOGE("PowerModeSettingsPlugin::DispatchGetPolicy unsupported item %{public}d", item);
            reply.WriteInt32(EdmReturnErrCode::EXECUTE_TIME_OUT);
            return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
}

ErrCode PowerModeSettingsPlugin::SetScreenOffTime(const std::string &valueStr, bool isAc)
{
    int32_t value = 0;
    if (!ParseScreenOffTime(valueStr, value)) {
        EDMLOGE("PowerModeSettingsPlugin::set screen off time param error.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (value < SCREEN_OFF_TIME_MIN_VALUE && value != SCREEN_OFF_TIME_NEVER_VALUE) {
        EDMLOGE("PowerModeSettingsPlugin::set screen off time param error.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (FAILED(EdmDataAbilityUtils::UpdateSettingsData(BatteryUtils::GetSubUserTableUri(),
        GetScreenOffTimeKey(isAc), std::to_string(value)))) {
        EDMLOGE("PowerModeSettingsPlugin::set screen off time failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string params = EdmJsonBuilder()
        .Add("item", "screenOff")
        .Add("value", std::to_string(value))
        .Build();
    IExtraPolicyNotification::GetInstance()->NotifyPolicyChanged(OverrideInterfaceName::DeviceSettings::SET_VALUE,
        params);
    return ERR_OK;
}

ErrCode PowerModeSettingsPlugin::GetScreenOffTime(MessageParcel &reply, bool isAc)
{
    int32_t result = 0;
    if (FAILED(EdmDataAbilityUtils::GetIntFromSettingsDataShare(BatteryUtils::GetSubUserTableUri(),
        GetScreenOffTimeKey(isAc), result))) {
        EDMLOGE("PowerModeSettingsPlugin::get screen off time from database failed.");
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteString(std::to_string(result));
    return ERR_OK;
}

ErrCode PowerModeSettingsPlugin::SetPowerPolicy(const std::string &valueStr, bool isAc)
{
    uint32_t powerScene = 0;
    PowerPolicy powerPolicy;
    if (!ParsePowerPolicy(valueStr, powerScene, powerPolicy)) {
        EDMLOGE("PowerModeSettingsPlugin:ParsePowerPolicy parse error");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::string policyKey;
    if (!GetPowerSceneKey(powerScene, policyKey)) {
        EDMLOGE("PowerModeSettingsPlugin:GetPowerSceneKey error");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (powerPolicy.GetDelayTime() == INVALID_DELAY_TIME) {
        EDMLOGE("PowerModeSettingsPlugin:delayTime can not be 30000.");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    if (DealPowerSuspendPolicy(policyKey, GetSuspendKey(isAc), powerPolicy, true)) {
        std::string powerPolicyJson = EdmJsonBuilder()
            .Add("powerPolicyAction", static_cast<uint32_t>(powerPolicy.GetPowerPolicyAction()))
            .Add("delayTime", static_cast<uint32_t>(powerPolicy.GetDelayTime()))
            .Build();
        std::string policy = EdmJsonBuilder()
            .Add("powerScene", static_cast<uint32_t>(PowerScene::TIME_OUT))
            .AddRawJson("powerPolicy", powerPolicyJson)
            .Build();
        std::string params = EdmJsonBuilder()
            .Add("item", "powerPolicy")
            .Add("value", policy)
            .Build();
        IExtraPolicyNotification::GetInstance()->NotifyPolicyChanged(OverrideInterfaceName::DeviceSettings::SET_VALUE,
            params);
        return ERR_OK;
    }
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode PowerModeSettingsPlugin::GetPowerPolicy(MessageParcel &reply, bool isAc)
{
    std::string policyKey = KEY_TIME_OUT;
    PowerPolicy powerPolicy;
    if (!DealPowerSuspendPolicy(policyKey, GetSuspendKey(isAc), powerPolicy, false)) {
        EDMLOGE("PowerModeSettingsPlugin:PowerPolicy parse error");
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string powerPolicyJson = EdmJsonBuilder()
        .Add(KEY_POWER_POLICY_ACTION, static_cast<uint32_t>(powerPolicy.GetPowerPolicyAction()))
        .Add(KEY_POWER_DELAY_TIME, static_cast<uint32_t>(powerPolicy.GetDelayTime()))
        .Build();
    std::string policy = EdmJsonBuilder()
        .Add(KEY_POWER_SCENE, static_cast<uint32_t>(PowerScene::TIME_OUT))
        .AddRawJson(KEY_POWER_POLICY, powerPolicyJson)
        .Build();
    reply.WriteInt32(ERR_OK);
    reply.WriteString(policy);
    return ERR_OK;
}

bool PowerModeSettingsPlugin::ParsePowerPolicy(const std::string &valueStr, uint32_t &powerScene,
    PowerPolicy &powerPolicy)
{
    cJSON *root = cJSON_Parse(valueStr.c_str());
    if (root == nullptr) {
        return false;
    }
    cJSON *sceneItem = cJSON_GetObjectItem(root, KEY_POWER_SCENE);
    cJSON *policyObj = cJSON_GetObjectItem(root, KEY_POWER_POLICY);
    cJSON *actionItem = policyObj == nullptr ? nullptr : cJSON_GetObjectItem(policyObj, KEY_POWER_POLICY_ACTION);
    cJSON *delayItem = policyObj == nullptr ? nullptr : cJSON_GetObjectItem(policyObj, KEY_POWER_DELAY_TIME);
    bool result = false;
    if (sceneItem != nullptr && cJSON_IsNumber(sceneItem) && actionItem != nullptr &&
        cJSON_IsNumber(actionItem) && delayItem != nullptr && cJSON_IsNumber(delayItem) &&
        delayItem->valueint >= 0 &&
        powerPolicy.SetPowerPolicyAction(actionItem->valueint)) {
        powerPolicy.SetDelayTime(static_cast<uint32_t>(delayItem->valueint));
        powerScene = static_cast<uint32_t>(sceneItem->valueint);
        result = true;
    }
    cJSON_Delete(root);
    return result;
}

bool PowerModeSettingsPlugin::DealPowerSuspendPolicy(const std::string &policyKey, const std::string &suspendKey,
    PowerPolicy &powerPolicy, bool isSetPolicy)
{
    std::string powerSuspend;
    if (FAILED(EdmDataAbilityUtils::GetStringFromSettingsDataShare(BatteryUtils::GetSubUserTableUri(),
        suspendKey, powerSuspend))) {
        return false;
    }

    cJSON *root = cJSON_Parse(powerSuspend.c_str());
    if (root == nullptr) {
        EDMLOGE("PowerModeSettingsPlugin:DealPowerSuspendPolicy parse error");
        return false;
    }

    cJSON *policyItem = cJSON_GetObjectItem(root, policyKey.c_str());
    if (policyItem == nullptr) {
        EDMLOGE("PowerModeSettingsPlugin:DealPowerSuspendPolicy %{public}s is not root member",
            policyKey.c_str());
        cJSON_Delete(root);
        return false;
    }

    bool result = false;
    if (isSetPolicy) {
        result = UpdateSuspendSettingsData(root, policyKey, suspendKey, powerPolicy);
    } else {
        result = SetPowerPolicyObject(root, policyKey, powerPolicy);
    }

    cJSON_Delete(root);
    return result;
}

bool PowerModeSettingsPlugin::UpdateSuspendSettingsData(cJSON* root, const std::string& key,
    const std::string& suspendKey, const PowerPolicy& powerPolicy)
{
    cJSON* valueObj = cJSON_GetObjectItem(root, key.c_str());
    if (valueObj == nullptr || !cJSON_IsObject(valueObj)) {
        return false;
    }

    cJSON* actionItem = cJSON_GetObjectItem(valueObj, KEY_ACTION);
    if (actionItem != nullptr) {
        cJSON_SetNumberValue(actionItem, static_cast<uint32_t>(powerPolicy.GetPowerPolicyAction()));
    } else {
        cJSON_AddNumberToObject(valueObj, KEY_ACTION, static_cast<uint32_t>(powerPolicy.GetPowerPolicyAction()));
    }

    cJSON* delayItem = cJSON_GetObjectItem(valueObj, KEY_DELAY_TIME);
    if (delayItem != nullptr) {
        cJSON_SetNumberValue(delayItem, powerPolicy.GetDelayTime());
    } else {
        cJSON_AddNumberToObject(valueObj, KEY_DELAY_TIME, powerPolicy.GetDelayTime());
    }

    char* jsonStr = cJSON_PrintUnformatted(root);
    if (jsonStr == nullptr) {
        return false;
    }
    EDMLOGD("PowerModeSettingsPlugin:OnSetPolicy jsonStr = %{public}s", jsonStr);
    if (FAILED(EdmDataAbilityUtils::UpdateSettingsData(BatteryUtils::GetSubUserTableUri(), suspendKey,
        jsonStr))) {
        cJSON_free(jsonStr);
        return false;
    }
    cJSON_free(jsonStr);
    return true;
}

bool PowerModeSettingsPlugin::SetPowerPolicyObject(cJSON* root, const std::string& key,
    PowerPolicy& powerPolicy)
{
    cJSON* valueObj = cJSON_GetObjectItem(root, key.c_str());
    if (valueObj == nullptr || !cJSON_IsObject(valueObj)) {
        return false;
    }

    cJSON* actionValue = cJSON_GetObjectItem(valueObj, KEY_ACTION);
    cJSON* delayValue = cJSON_GetObjectItem(valueObj, KEY_DELAY_TIME);

    if (actionValue && cJSON_IsNumber(actionValue) && delayValue && cJSON_IsNumber(delayValue) &&
        delayValue->valueint >= 0) {
        if (!powerPolicy.SetPowerPolicyAction(actionValue->valueint)) {
            return false;
        }
        powerPolicy.SetDelayTime(static_cast<uint32_t>(delayValue->valueint));
        return true;
    }
    return false;
}

bool PowerModeSettingsPlugin::GetPowerSceneKey(const uint32_t &powerScene, std::string &sceneKey)
{
    if (powerScene == static_cast<uint32_t>(PowerScene::TIME_OUT)) {
        sceneKey = KEY_TIME_OUT;
        return true;
    }
    return false;
}
} // namespace EDM
} // namespace OHOS
