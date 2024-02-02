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

#include "get_device_encryption_status_plugin.h"

#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "string_serializer.h"
#include "plugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(GetDeviceEncryptionStatusPlugin::GetPlugin());

void GetDeviceEncryptionStatusPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<GetDeviceEncryptionStatusPlugin,
    std::string>> ptr)
{
    EDMLOGI("GetDeviceEncryptionStatusPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::GET_DEVICE_ENCRYPTION_STATUS, "get_device_encryption_status",
        "ohos.permission.ENTERPRISE_MANAGE_SECURITY", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
}

ErrCode GetDeviceEncryptionStatusPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("GetDeviceEncryptionStatusPlugin OnGetPolicy.");
    std::string res = system::GetParameter("fscrypt.policy.config", "");
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(!res.empty());
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS