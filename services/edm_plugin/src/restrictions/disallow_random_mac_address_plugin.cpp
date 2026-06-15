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

#include "disallow_random_mac_address_plugin.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "wifi_device.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<DisallowRandomMacAddressPlugin>());

DisallowRandomMacAddressPlugin::DisallowRandomMacAddressPlugin()
{
    EDMLOGI("DisallowRandomMacAddressPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOWED_RANDOM_MAC_ADDRESS;
    policyName_ = PolicyName::POLICY_DISALLOWED_RANDOM_MAC_ADDRESS;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    persistParam_ = "persist.edm.random_mac_address_disable";
}

ErrCode DisallowRandomMacAddressPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisallowRandomMacAddressPlugin SetOtherModulePolicy");
    auto wifiDevice = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID);
    if (wifiDevice == nullptr) {
        EDMLOGE("wifiDevice GetInstance null");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode ret = wifiDevice->SetRandomMacDisabled(data);
    if (ret != ERR_OK) {
        EDMLOGI("DisallowRandomMacAddressPlugin: wifi device set random mac failed ret: %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS