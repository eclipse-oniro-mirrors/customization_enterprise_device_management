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
#include "switch_wifi_plugin.h"

#include "parameters.h"
#include "wifi_device.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "func_code_utils.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<SwitchWifiPlugin>());
const std::string MDM_WIFI_PROP = "persist.edm.wifi_enable";
const std::string PARAM_FORCE_OPEN_WIFI = "persist.edm.force_open_wifi";

SwitchWifiPlugin::SwitchWifiPlugin()
{
    EDMLOGI("SwitchWifiPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::SWITCH_WIFI;
    policyName_ = "switch_wifi";
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode SwitchWifiPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    bool handelData = data.ReadBool();
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    ErrCode result = ERR_OK;
    if (type == FuncOperateType::SET) {
        result = OnTurnOnPolicy(handelData);
    } else if (type == FuncOperateType::REMOVE) {
        result = OnTurnOffPolicy();
    }
    if (result != ERR_OK) {
        return result;
    }
    std::string afterHandle = handelData ? EdmConstants::CONST_TRUE : EdmConstants::CONST_FALSE;
    policyData.isChanged = (policyData.policyData != afterHandle);
    policyData.policyData = afterHandle;
    policyData.mergePolicyData = afterHandle;
    return ERR_OK;
}

ErrCode SwitchWifiPlugin::OnTurnOnPolicy(bool isForce)
{
    EDMLOGI("SwitchWifiPlugin OnSetPolicy isForce %{public}d", isForce);
    if (system::GetBoolParameter(MDM_WIFI_PROP.c_str(), false)) {
        EDMLOGE("SwitchWifiPlugin OnTurnOnPolicy failed, because wifi disabled");
        return EdmReturnErrCode::ENTERPRISE_POLICES_DENIED;
    }

    std::shared_ptr<Wifi::WifiDevice> devicePtr = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    if (devicePtr == nullptr) {
        EDMLOGE("SwitchWifiPlugin:OnTurnOnPolicy WifiDevice null");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int ret = devicePtr->EnableWifi();
    if (ret != Wifi::WIFI_OPT_SUCCESS || !system::SetParameter(PARAM_FORCE_OPEN_WIFI, isForce ? "true" : "false")) {
        EDMLOGE("SwitchWifiPlugin:OnTurnOnPolicy SetParameter fail or send request fail. %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode SwitchWifiPlugin::OnTurnOffPolicy()
{
    if (system::GetBoolParameter(MDM_WIFI_PROP.c_str(), false)) {
        EDMLOGE("SwitchWifiPlugin OnTurnOffPolicy failed, because wifi disabled");
        return EdmReturnErrCode::ENTERPRISE_POLICES_DENIED;
    }

    if (!system::SetParameter(PARAM_FORCE_OPEN_WIFI, "false")) {
        EDMLOGE("SwitchWifiPlugin:OnTurnOffPolicy SetParameter fail. ");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    std::shared_ptr<Wifi::WifiDevice> devicePtr = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    if (devicePtr == nullptr) {
        EDMLOGE("SwitchWifiPlugin:OnTurnOffPolicy WifiDevice null");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int ret = devicePtr->DisableWifi();
    if (ret != Wifi::WIFI_OPT_SUCCESS) {
        EDMLOGE("SwitchWifiPlugin:OnTurnOffPolicy send request fail. %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode SwitchWifiPlugin::OnAdminRemove(const std::string &adminName, const std::string &policyData,
    const std::string &mergeData, int32_t userId)
{
    EDMLOGI("SwitchWifiPlugin OnAdminRemove");
    system::SetParameter(PARAM_FORCE_OPEN_WIFI, "false");
    return ERR_OK;
}

} // namespace EDM
} // namespace OHOS