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
 
#include "set_switch_status_plugin.h"
 
#include "bluetooth_def.h"
#include "bluetooth_errorcode.h"
#include "bluetooth_host.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "parameters.h"
#include "wifi_device.h"
 
namespace OHOS {
namespace EDM {

const std::string MDM_BLUETOOTH_PROP = "persist.edm.prohibit_bluetooth";
const std::string MDM_WIFI_PROP = "persist.edm.wifi_enable";
const std::string PARAM_FORCE_OPEN_WIFI = "persist.edm.force_open_wifi";
 
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetSwitchStatusPlugin::GetPlugin());
 
void SetSwitchStatusPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SetSwitchStatusPlugin, SwitchParam>> ptr)
{
    EDMLOGI("SetSwitchStatusPlugin InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SETTINGS);
    typePermissions.emplace(IPlugin::PermissionType::BYOD_DEVICE_ADMIN,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::SET_SWITCH_STATUS, PolicyName::POLICY_SET_SWITCH_STATUS, config, false);
    ptr->SetSerializer(SwitchParamSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetSwitchStatusPlugin::OnSetPolicy, FuncOperateType::SET);
}
 
ErrCode SetSwitchStatusPlugin::OnSetPolicy(SwitchParam &param, MessageParcel &reply)
{
    int32_t ret = ERR_OK;
    EDMLOGI("SetSwitchStatusPlugin OnSetPolicy %{public}d, %{public}d",
        static_cast<int32_t>(param.key), static_cast<int32_t>(param.status));
    switch (param.key) {
        case SwitchKey::BLUETOOTH:
            ret = OnSetBluetoothStatus(param.status);
            break;
        case SwitchKey::WIFI:
            ret = OnSetWifiStatus(param.status);
            break;
        default:
            ret = EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    reply.WriteInt32(ret);
    if (ret == EdmReturnErrCode::INTERFACE_UNSUPPORTED) {
        SwitchParamSerializer::GetInstance()->WritePolicy(reply, param);
    }
    return ret;
}

ErrCode SetSwitchStatusPlugin::OnSetBluetoothStatus(SwitchStatus status)
{
    if (system::GetBoolParameter(MDM_BLUETOOTH_PROP, false)) {
        EDMLOGE("SetSwitchStatusPlugin OnSetBluetoothStatus failed, because bluetooth disabled");
        return EdmReturnErrCode::ENTERPRISE_POLICES_DENIED;
    }
    int32_t ret = Bluetooth::BT_NO_ERROR;
    if (status == SwitchStatus::ON) {
        ret = Bluetooth::BluetoothHost::GetDefaultHost().EnableBle();
    } else if (status == SwitchStatus::OFF) {
        ret = Bluetooth::BluetoothHost::GetDefaultHost().DisableBt();
    } else {
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    if (ret != Bluetooth::BT_NO_ERROR) {
        EDMLOGE("SetSwitchStatusPlugin:OnSetBluetoothStatus send request fail. %{public}d", ret);
    }
    return ERR_OK;
}

ErrCode SetSwitchStatusPlugin::OnSetWifiStatus(SwitchStatus status)
{
    if (system::GetBoolParameter(MDM_WIFI_PROP, false)) {
        EDMLOGE("SetSwitchStatusPlugin OnSetWifiStatus failed, because wifi disabled");
        return EdmReturnErrCode::ENTERPRISE_POLICES_DENIED;
    }
    if (!system::SetParameter(PARAM_FORCE_OPEN_WIFI, "false")) {
        EDMLOGE("SetSwitchStatusPlugin:OnSetWifiStatus SetParameter fail. ");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::shared_ptr<Wifi::WifiDevice> devicePtr = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    if (devicePtr == nullptr) {
        EDMLOGE("SetSwitchStatusPlugin:OnSetWifiStatus WifiDevice null");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = Wifi::WIFI_OPT_SUCCESS;
    if (status == SwitchStatus::ON) {
        ret = devicePtr->EnableWifi();
    } else if (status == SwitchStatus::OFF) {
        ret = devicePtr->DisableWifi();
    } else {
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    if (ret != Wifi::WIFI_OPT_SUCCESS) {
        EDMLOGE("SetSwitchStatusPlugin:OnSetWifiStatus send request fail. %{public}d", ret);
    }
    return ERR_OK;
}

SetSwitchStatusPlugin::~SetSwitchStatusPlugin()
{
    Bluetooth::BluetoothHost::GetDefaultHost().Close();
}
} // namespace EDM
} // namespace OHOS