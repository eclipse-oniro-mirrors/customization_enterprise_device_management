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
#include "edm_utils.h"
#include "wifi_device.h"
#include "wifi_device_config_serializer.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetWifiProfilePlugin::GetPlugin());

void SetWifiProfilePlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<SetWifiProfilePlugin, Wifi::WifiDeviceConfig>> ptr)
{
    EDMLOGI("SetWifiProfilePlugin InitPlugin...");
    std::map<std::string, std::map<IPlugin::PermissionType, std::string>> tagPermissions;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag11;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag12;
    typePermissionsForTag11.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_SET_WIFI);
    typePermissionsForTag12.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_WIFI);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_11, typePermissionsForTag11);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_12, typePermissionsForTag12);

    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(tagPermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::SET_WIFI_PROFILE, PolicyName::POLICY_SET_WIFI_PROFILE, config, false);
    ptr->SetSerializer(WifiDeviceConfigSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetWifiProfilePlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode SetWifiProfilePlugin::OnSetPolicy(Wifi::WifiDeviceConfig &config)
{
    EDMLOGD("SetWifiProfilePlugin OnSetPolicy");
    auto wifiDevice = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    if (wifiDevice == nullptr) {
        EDMLOGE("wifiDevice GetInstance null");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode ret = wifiDevice->ConnectToDevice(config);
    EdmUtils::ClearString(config.preSharedKey);
    if (sizeof(config.wepKeys) / sizeof(std::string) > 0) {
        EdmUtils::ClearString(config.wepKeys[0]);
    }
    EdmUtils::ClearString(config.wifiEapConfig.password);
    memset_s(config.wifiEapConfig.certPassword, sizeof(config.wifiEapConfig.certPassword), 0,
        sizeof(config.wifiEapConfig.certPassword));
    if (ret != ERR_OK) {
        EDMLOGE("SetWifiProfilePlugin ConnectToDevice ret %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
