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

#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code_utils.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(std::make_shared<PowerPolicyPlugin>());

const std::string KEY_POWER_SUSPEND = "settings.power.suspend_sources";
const std::string KEY_ACTION = "action";
const std::string KEY_DELAY_TIME = "delayMs";
const std::string KEY_TIME_OUT = "timeout";

PowerPolicyPlugin::PowerPolicyPlugin()
{
    policyCode_ = EdmInterfaceCode::POWER_POLICY;
    policyName_ = "power_policy";
    permissionConfig_.permission = "ohos.permission.ENTERPRISE_MANAGE_SETTINGS";
    permissionConfig_.permissionType = IPlugin::PermissionType::SUPER_DEVICE_ADMIN;
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
    if (FAILED(EdmDataAbilityUtils::GetStringFromSettingsDataShare(KEY_POWER_SUSPEND, powerSuspend))) {
        return false;
    }
    Json::Reader reader;
    Json::Value root;
    if (!reader.parse(powerSuspend.data(), powerSuspend.data() + powerSuspend.size(), root)) {
        EDMLOGE("PowerPolicyPlugin:DealPowerSuspendPolicy parse error");
        return false;
    }
    if (!root.isMember(policyKey)) {
        EDMLOGE("PowerPolicyPlugin:DealPowerSuspendPolicy %{pubilc}s is not root member", policyKey.c_str());
        return false;
    }
    Json::Value::Members members = root.getMemberNames();
    for (auto iter = members.begin(); iter != members.end(); iter++) {
        std::string key = *iter;
        if (key != policyKey) {
            continue;
        }
        if (isSetPolicy) {
            return UpdateSuspendSettingsData(root, key, powerPolicy);
        }
        return SetPowerPolicyObject(root, key, powerPolicy);
    }
    return false;
}

bool PowerPolicyPlugin::UpdateSuspendSettingsData(Json::Value &root, const std::string &key,
    const PowerPolicy &powerPolicy)
{
    Json::Value valueObj = root[key];
    if (!valueObj.isObject()) {
        return false;
    }
    valueObj[KEY_ACTION] = static_cast<uint32_t>(powerPolicy.GetPowerPolicyAction());
    valueObj[KEY_DELAY_TIME] = powerPolicy.GetDealyTime();
    root[key] = valueObj;
    std::string jsonStr = root.toStyledString();
    EDMLOGD("PowerPolicyPlugin:OnSetPolicy jsonStr = %{public}s", jsonStr.c_str());
    if (FAILED(EdmDataAbilityUtils::UpdateSettingsData(KEY_POWER_SUSPEND, jsonStr))) {
        return false;
    }
    return true;
}

bool PowerPolicyPlugin::SetPowerPolicyObject(Json::Value &root, std::string &key, PowerPolicy &powerPolicy)
{
    Json::Value valueObj = root[key];
    if (!valueObj.isObject()) {
        return false;
    }
    Json::Value actionValue = valueObj[KEY_ACTION];
    Json::Value delayValue = valueObj[KEY_DELAY_TIME];
    if (actionValue.isUInt() && delayValue.isUInt()) {
        if (!powerPolicy.SetPowerPolicyAction(actionValue.asUInt())) {
            return false;
        }
        powerPolicy.SetDelayTime(delayValue.asUInt());
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
