/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "set_wifi_disabled_plugin.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "wifi_device.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(SetWifiDisabledPlugin::GetPlugin());
const std::string KEY_DISABLE_WIFI = "persist.edm.wifi_enable";

void SetWifiDisabledPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SetWifiDisabledPlugin, bool>> ptr)
{
    EDMLOGI("SetWifiDisabledPlugin InitPlugin...");
    std::map<std::string, std::map<IPlugin::PermissionType, std::string>> tagPermissions;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag11;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag12;
    typePermissionsForTag11.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        "ohos.permission.ENTERPRISE_MANAGE_WIFI");
    typePermissionsForTag12.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS");
    typePermissionsForTag12.emplace(IPlugin::PermissionType::BYOD_DEVICE_ADMIN,
        "ohos.permission.PERSONAL_MANAGE_RESTRICTIONS");
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_11, typePermissionsForTag11);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_12, typePermissionsForTag12);

    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(tagPermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_WIFI, "disable_wifi", config, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetWifiDisabledPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&SetWifiDisabledPlugin::OnAdminRemove);
}

ErrCode SetWifiDisabledPlugin::OnSetPolicy(bool &isDisable)
{
    EDMLOGI("SetWifiDisabledPlugin OnSetPolicy %{public}d", isDisable);
    std::string value = isDisable ? "true" : "false";
    if (isDisable) {
        ErrCode ret = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID)->DisableWifi();
        if (ret != ERR_OK) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return system::SetParameter(KEY_DISABLE_WIFI, value) ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode SetWifiDisabledPlugin::OnAdminRemove(const std::string &adminName, bool &data, int32_t userId)
{
    EDMLOGI("SetWifiDisabledPlugin OnAdminRemove %{public}d...", data);
    if (!data) {
        return ERR_OK;
    }
    bool reset = false;
    return OnSetPolicy(reset);
}

ErrCode SetWifiDisabledPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("SetWifiDisabledPlugin OnGetPolicy.");
    bool ret = system::GetBoolParameter(KEY_DISABLE_WIFI, false);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(ret);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
