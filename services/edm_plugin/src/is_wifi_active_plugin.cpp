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

#include "is_wifi_active_plugin.h"

#include <system_ability_definition.h>

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "wifi_device.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(IsWifiActivePlugin::GetPlugin());

void IsWifiActivePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<IsWifiActivePlugin, bool>> ptr)
{
    EDMLOGI("IsWifiActivePlugin InitPlugin...");
    std::map<std::string, std::string> perms;
    perms.insert(std::make_pair(EdmConstants::PERMISSION_TAG_VERSION_11, "ohos.permission.ENTERPRISE_SET_WIFI"));
    perms.insert(std::make_pair(EdmConstants::PERMISSION_TAG_VERSION_12, "ohos.permission.ENTERPRISE_MANAGE_WIFI"));
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(perms,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::IS_WIFI_ACTIVE, "is_wifi_active", config, false);
    ptr->SetSerializer(BoolSerializer::GetInstance());
}

ErrCode IsWifiActivePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId) __attribute__((no_sanitize("cfi")))
{
    EDMLOGD("IsWifiActivePlugin OnGetPolicy.");
    bool isActive = false;
    ErrCode ret = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID)->IsWifiActive(isActive);
    if (ret != ERR_OK) {
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isActive);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
