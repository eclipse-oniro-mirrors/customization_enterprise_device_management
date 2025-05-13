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
#include "turnoff_wifi_plugin.h"

#include "parameters.h"
#include "wifi_device.h"
 
#include "int_serializer.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
 
namespace OHOS {
namespace EDM {
 
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(TurnOffWifiPlugin::GetPlugin());
const std::string PARAM_FORCE_OPEN_WIFI = "persist.edm.force_open_wifi";
 
void TurnOffWifiPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<TurnOffWifiPlugin, int32_t>> ptr)
{
    EDMLOGI("TurnOffWifiPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::TURNOFF_WIFI, "turnoff_wifi",
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(IntSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&TurnOffWifiPlugin::OnSetPolicy, FuncOperateType::SET);
}
 
ErrCode TurnOffWifiPlugin::OnSetPolicy()
{
    EDMLOGI("TurnOffWifiPlugin OnSetPolicy");
    if (!system::SetParameter(PARAM_FORCE_OPEN_WIFI, "false")) {
        EDMLOGE("TurnOffWifiPlugin:OnSetPolicy SetParameter fail. ");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::shared_ptr<Wifi::WifiDevice> devicePtr = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    int ret = devicePtr->DisableWifi();
    if (ret != Wifi::WIFI_OPT_SUCCESS) {
        EDMLOGE("TurnOffWifiPlugin:OnSetPolicy send request fail. %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

} // namespace EDM
} // namespace OHOS