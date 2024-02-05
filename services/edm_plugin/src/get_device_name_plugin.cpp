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

#include "get_device_name_plugin.h"

#include "edm_data_ability_utils.h"
#include "edm_ipc_interface_code.h"
#include "parameter.h"
#include "string_serializer.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const std::string KEY_DEVICE_NAME = "settings.general.device_name";

const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(GetDeviceNamePlugin::GetPlugin());

void GetDeviceNamePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<GetDeviceNamePlugin, std::string>> ptr)
{
    EDMLOGI("GetDeviceNamePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::GET_DEVICE_NAME, "get_device_name",
        "ohos.permission.ENTERPRISE_GET_DEVICE_INFO", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
}

ErrCode GetDeviceNamePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("GetDeviceNamePlugin OnGetPolicy GetMarketName");
    std::string name;
    ErrCode code = EdmDataAbilityUtils::GetStringFromSettingsDataShare(KEY_DEVICE_NAME, name);
    if (code != ERR_OK) {
        EDMLOGD("GetDeviceNamePlugin::get device name from database failed : %{public}d.", code);
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
} // namespace EDM
} // namespace OHOS
