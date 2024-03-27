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

#include "set_wifi_profile_plugin.h"

#include <system_ability_definition.h>

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "wifi_device.h"
#include "wifi_device_config_serializer.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(SetWifiProfilePlugin::GetPlugin());

void SetWifiProfilePlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<SetWifiProfilePlugin, Wifi::WifiDeviceConfig>> ptr)
{
    EDMLOGI("SetWifiProfilePlugin InitPlugin...");
    std::map<std::string, std::string> perms;
    perms.insert(std::make_pair(EdmConstants::PERMISSION_TAG_VERSION_11, "ohos.permission.ENTERPRISE_SET_WIFI"));
    perms.insert(std::make_pair(EdmConstants::PERMISSION_TAG_VERSION_12, "ohos.permission.ENTERPRISE_MANAGE_WIFI"));
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(perms,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::SET_WIFI_PROFILE, "set_wifi_profile", config, false);
    ptr->SetSerializer(WifiDeviceConfigSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetWifiProfilePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode SetWifiProfilePlugin::OnSetPolicy(Wifi::WifiDeviceConfig &config) __attribute__((no_sanitize("cfi")))
{
    EDMLOGD("SetWifiProfilePlugin OnSetPolicy");
    ErrCode ret = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID)->ConnectToDevice(config);
    if (ret != ERR_OK) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
