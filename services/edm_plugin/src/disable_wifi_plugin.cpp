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

#include "disable_wifi_plugin.h"

#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "parameters.h"
#include "wifi_device.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableWifiPlugin::GetPlugin());
const std::string KEY_DISABLE_WIFI = "persist.edm.wifi_enable";

void DisableWifiPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableWifiPlugin, bool>> ptr)
{
    EDMLOGD("DisableWifiPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_WIFI, "disable_wifi",
        "ohos.permission.ENTERPRISE_MANAGE_WIFI", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableWifiPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode DisableWifiPlugin::OnSetPolicy(bool &isDisable) __attribute__((no_sanitize("cfi")))
{
    EDMLOGI("DisableWifiPlugin OnSetPolicy %{public}d", isDisable);
    std::string value = isDisable ? "true" : "false";
    if (isDisable) {
        ErrCode ret = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_ABILITY_ID)->DisableWifi();
        if (ret != ERR_OK) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return system::SetParameter(KEY_DISABLE_WIFI, value) ? ERR_OK : EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode DisableWifiPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("DisableWifiPlugin OnGetPolicy.");
    bool ret = system::GetBoolParameter(KEY_DISABLE_WIFI, false);
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(ret);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
