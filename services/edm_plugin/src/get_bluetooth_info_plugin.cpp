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
#include "edm_ipc_interface_code.h"
#include "get_bluetooth_info_plugin.h"
#include "iedm_bluetooth_manager.h"
#include "parameters.h"
#include "string_serializer.h"
#include "iplugin_manager.h"


namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(GetBluetoothInfoPlugin::GetPlugin());

void GetBluetoothInfoPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<GetBluetoothInfoPlugin,
    std::string>> ptr)
{
    EDMLOGI("GetBluetoothInfoPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::GET_BLUETOOTH_INFO, PolicyName::POLICY_GET_BLUETOOTH_INFO,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
}

ErrCode GetBluetoothInfoPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("GetBluetoothInfoPlugin OnGetPolicy.");
    std::string name = IEdmBluetoothManager::GetInstance()->GetLocalName();
    int32_t realState = IEdmBluetoothManager::GetInstance()->GetBtState();
    int32_t realConnectionState = IEdmBluetoothManager::GetInstance()->GetBtConnectionState();
    if (realState == -1 || realConnectionState == -1) {
        EDMLOGD("GetBluetoothInfoPlugin::get bluetooth info failed.State or connectionState is illegally.");
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteString(name);
    reply.WriteInt32(realState);
    reply.WriteInt32(realConnectionState);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS