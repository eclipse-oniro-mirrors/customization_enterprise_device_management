/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "power_policy_plugin.h"

#include "battery_utils.h"
#include "edm_constants.h"
#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<PowerPolicyPlugin>());

const std::string KEY_POWER_SUSPEND = "settings.power.suspend_sources";
const std::string KEY_POWER_AC_SUSPEND = "settings.power.ac.suspend_sources";
const std::string KEY_POWER_DC_SUSPEND = "settings.power.dc.suspend_sources";
const std::string KEY_TIME_OUT = "timeout";
const char* const KEY_ACTION = "action";
const char* const KEY_DELAY_TIME = "delayMs";

PowerPolicyPlugin::PowerPolicyPlugin()
{
    policyCode_ = EdmInterfaceCode::POWER_POLICY;
    policyName_ = PolicyName::POLICY_POWER_POLICY;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

ErrCode PowerPolicyPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    if (type == FuncOperateType::SET) {
        return SetPowerPolicy(data);
    }
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode PowerPolicyPlugin::SetPowerPolicy(MessageParcel &data)
{
    uint32_t powerSence = data.ReadUint32();
    PowerPolicy powerPolicy;
    if (!PowerPolicy::Unmarshalling(data, powerPolicy)) {
        EDMLOGE("PowerPolicyPlugin:Unmarshalling parse error");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::string policyKey;
    if (!GetPowerSceneKey(powerSence, policyKey)) {
        EDMLOGE("PowerPolicyPlugin:GetPowerSceneKey error");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    if (DealPowerSuspendPolicy(policyKey, powerPolicy, true)) {
        return ERR_OK;
    }
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode PowerPolicyPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    uint32_t powerSence = data.ReadUint32();
    std::string policyKey;
    if (!GetPowerSceneKey(powerSence, policyKey)) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    PowerPolicy powerPolicy;
    if (!DealPowerSuspendPolicy(policyKey, powerPolicy, false)) {
        EDMLOGE("PowerPolicyPlugin:PowerPolicy parse error");
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    if (!powerPolicy.Marshalling(reply)) {
        EDMLOGE("PowerPolicyPlugin:OnGetPolicy Marshalling error");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

bool PowerPolicyPlugin::DealPowerSuspendPolicy(const std::string &policyKey, PowerPolicy &powerPolicy, bool isSetPolicy)
{
    std::string powerSuspend;
#ifdef FEATURE_CHARGING_TYPE_SETTING
    std::string newKey;
    if (BatteryUtils::GetBatteryPluggedType() == BatteryUtils::PLUGGED_TYPE_AC) {
        newKey = KEY_POWER_AC_SUSPEND;
    } else {
        newKey = KEY_POWER_DC_SUSPEND;
    }
    if (FAILED(EdmDataAbilityUtils::GetStringFromSettingsDataShare(
        BatteryUtils::GetSubUserTableUri(), newKey, powerSuspend))) {
        return false;
    }
#else
    if (FAILED(EdmDataAbilityUtils::GetStringFromSettingsDataShare(KEY_POWER_SUSPEND, powerSuspend))) {
        return false;
    }
#endif

    cJSON *root = cJSON_Parse(powerSuspend.c_str());
    if (root == nullptr) {
        EDMLOGE("PowerPolicyPlugin:DealPowerSuspendPolicy parse error");
        return false;
    }

    cJSON *policyItem = cJSON_GetObjectItem(root, policyKey.c_str());
    if (policyItem == nullptr) {
        EDMLOGE("PowerPolicyPlugin:DealPowerSuspendPolicy %{public}s is not root member", policyKey.c_str());
        cJSON_Delete(root);
        return false;
    }

    bool result = false;
    if (isSetPolicy) {
        result = UpdateSuspendSettingsData(root, policyKey, powerPolicy);
    } else {
        result = SetPowerPolicyObject(root, policyKey, powerPolicy);
    }

    cJSON_Delete(root);
    return result;
}

bool PowerPolicyPlugin::UpdateSuspendSettingsData(cJSON* root, const std::string& key,
    const PowerPolicy& powerPolicy)
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
    EDMLOGD("PowerPolicyPlugin:OnSetPolicy jsonStr = %{public}s", jsonStr);

#ifdef FEATURE_CHARGING_TYPE_SETTING
    if (FAILED(EdmDataAbilityUtils::UpdateSettingsData(
        BatteryUtils::GetSubUserTableUri(), KEY_POWER_AC_SUSPEND, jsonStr))) {
        cJSON_free(jsonStr);
        return false;
    }
    if (FAILED(EdmDataAbilityUtils::UpdateSettingsData(
        BatteryUtils::GetSubUserTableUri(), KEY_POWER_DC_SUSPEND, jsonStr))) {
        cJSON_free(jsonStr);
        return false;
    }
#else
    if (FAILED(EdmDataAbilityUtils::UpdateSettingsData(KEY_POWER_SUSPEND, jsonStr))) {
        cJSON_free(jsonStr);
        return false;
    }
#endif

    cJSON_free(jsonStr);
    return true;
}

bool PowerPolicyPlugin::SetPowerPolicyObject(cJSON* root, const std::string& key, PowerPolicy& powerPolicy)
{
    cJSON* valueObj = cJSON_GetObjectItem(root, key.c_str());
    if (valueObj == nullptr || !cJSON_IsObject(valueObj)) {
        return false;
    }

    cJSON* actionValue = cJSON_GetObjectItem(valueObj, KEY_ACTION);
    cJSON* delayValue = cJSON_GetObjectItem(valueObj, KEY_DELAY_TIME);

    if (actionValue && cJSON_IsNumber(actionValue) && delayValue && cJSON_IsNumber(delayValue)) {
        if (!powerPolicy.SetPowerPolicyAction(actionValue->valueint)) {
            return false;
        }
        powerPolicy.SetDelayTime(delayValue->valueint);
        return true;
    }
    return false;
}

bool PowerPolicyPlugin::GetPowerSceneKey(const uint32_t &powerScene, std::string &sceneKey)
{
    if (powerScene == static_cast<uint32_t>(PowerScene::TIME_OUT)) {
        sceneKey = KEY_TIME_OUT;
        return true;
    }
    return false;
}
} // namespace EDM
} // namespace OHOS
