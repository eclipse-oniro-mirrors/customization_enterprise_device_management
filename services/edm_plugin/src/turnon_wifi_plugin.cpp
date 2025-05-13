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
#include "turnon_wifi_plugin.h"

#include "parameters.h"
#include "wifi_device.h"
 
#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
 
namespace OHOS {
namespace EDM {
 
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(TurnOnWifiPlugin::GetPlugin());
const std::string PARAM_FORCE_OPEN_WIFI = "persist.edm.force_open_wifi";
 
void TurnOnWifiPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<TurnOnWifiPlugin, bool>> ptr)
{
    EDMLOGI("TurnOnWifiPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::TURNON_WIFI, "turnon_wifi",
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&TurnOnWifiPlugin::OnSetPolicy, FuncOperateType::SET);
}
 
ErrCode TurnOnWifiPlugin::OnSetPolicy(bool &isForce)
{
    EDMLOGI("TurnOnWifiPlugin OnSetPolicy isForce %{public}d", isForce);
    std::shared_ptr<Wifi::WifiDevice> devicePtr = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    int ret = devicePtr->EnableWifi();
    if (ret != Wifi::WIFI_OPT_SUCCESS || !system::SetParameter(PARAM_FORCE_OPEN_WIFI, isForce ? "true" : "false")) {
        EDMLOGE("TurnOnWifiPlugin:OnSetPolicy SetParameter fail or send request fail. %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
 
} // namespace EDM
} // namespace OHOS