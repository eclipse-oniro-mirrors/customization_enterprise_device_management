/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "get_device_info_plugin.h"

#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "parameter.h"
#include "plugin_manager.h"
#include "string_serializer.h"

namespace OHOS {
namespace EDM {
const std::string KEY_DEVICE_NAME = "settings.general.device_name";

const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(GetDeviceInfoPlugin::GetPlugin());

void GetDeviceInfoPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<GetDeviceInfoPlugin, std::string>> ptr)
{
    EDMLOGI("GetDeviceInfoPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::GET_DEVICE_INFO, "get_device_info",
        "ohos.permission.ENTERPRISE_GET_DEVICE_INFO", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
}

ErrCode GetDeviceInfoPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    std::string label = data.ReadString();
    EDMLOGI("GetDeviceInfoPlugin OnGetPolicy GetDeviceInfo %{public}s", label.c_str());
    if (label == EdmConstants::DeviceInfo::DEVICE_NAME) {
        std::string name;
        ErrCode code = EdmDataAbilityUtils::GetStringFromSettingsDataShare(KEY_DEVICE_NAME, name);
        if (FAILED(code)) {
            EDMLOGD("GetDeviceInfoPlugin::get device name from database failed : %{public}d.", code);
            reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        if (name.empty()) {
            name = GetMarketName();
        }
        reply.WriteInt32(ERR_OK);
        reply.WriteString(name);
        return ERR_OK;
    }
    if (label == EdmConstants::DeviceInfo::DEVICE_SERIAL) {
        std::string serial = GetSerial();
        reply.WriteInt32(ERR_OK);
        reply.WriteString(serial);
        return ERR_OK;
    }
    reply.WriteInt32(EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    if (GetPlugin()->GetExtensionPlugin() != nullptr) {
        reply.WriteString(label);
    }
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS
