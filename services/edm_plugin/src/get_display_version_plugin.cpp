/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "get_display_version_plugin.h"

#include "edm_ipc_interface_code.h"
#include "parameter.h"
#include "string_serializer.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(GetDisplayVersionPlugin::GetPlugin());

void GetDisplayVersionPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<GetDisplayVersionPlugin, std::string>> ptr)
{
    EDMLOGI("GetDisplayVersionPlugin InitPlugin...");
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(
        "ohos.permission.ENTERPRISE_GET_DEVICE_INFO",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::SYSTEM);
    ptr->InitAttribute(EdmInterfaceCode::GET_DISPLAY_VERSION, "get_display_version", config, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
}

ErrCode GetDisplayVersionPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("GetDisplayVersionPlugin OnGetPolicy.");
    std::string version = GetDisplayVersion();
    reply.WriteInt32(ERR_OK);
    reply.WriteString(version);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
