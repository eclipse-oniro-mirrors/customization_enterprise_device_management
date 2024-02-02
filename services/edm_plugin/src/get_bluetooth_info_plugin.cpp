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
#include "bluetooth_def.h"
#include "bluetooth_host.h"
#include "edm_ipc_interface_code.h"
#include "get_bluetooth_info_plugin.h"
#include "parameters.h"
#include "string_serializer.h"
#include "plugin_manager.h"


namespace OHOS {
namespace EDM {
enum BluetoothState {
    TURN_OFF,
    TURNING_ON,
    TURN_ON,
    TURNING_OFF,
};

enum BluetoothConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    DISCONNECTING,
};

const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(GetBluetoothInfoPlugin::GetPlugin());

void GetBluetoothInfoPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<GetBluetoothInfoPlugin,
    std::string>> ptr)
{
    EDMLOGI("GetBluetoothInfoPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::GET_BLUETOOTH_INFO, "get_bluetooth_info",
        "ohos.permission.ENTERPRISE_MANAGE_BLUETOOTH", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(StringSerializer::GetInstance());
}

int32_t GetBluetoothInfoPlugin::TransformBluetoothState(int32_t state)
{
    int32_t realState;
    switch (state) {
        case static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURNING_ON):
            realState = BluetoothState::TURNING_ON;
            break;
        case static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_ON):
            realState = BluetoothState::TURN_ON;
            break;
        case static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURNING_OFF):
            realState = BluetoothState::TURNING_OFF;
            break;
        case static_cast<int32_t>(Bluetooth::BTStateID::STATE_TURN_OFF):
            realState = BluetoothState::TURN_OFF;
            break;
        default:
            realState = -1;
    }
    return realState;
}

int32_t GetBluetoothInfoPlugin::TransformBluetoothConnectionState(int32_t connectionState)
{
    int32_t realConnectionState;
    switch (connectionState) {
        case static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTING):
            realConnectionState = BluetoothConnectionState::CONNECTING;
            break;
        case static_cast<int32_t>(Bluetooth::BTConnectState::CONNECTED):
            realConnectionState = BluetoothConnectionState::CONNECTED;
            break;
        case static_cast<int32_t>(Bluetooth::BTConnectState::DISCONNECTING):
            realConnectionState = BluetoothConnectionState::DISCONNECTING;
            break;
        case static_cast<int32_t>(Bluetooth::BTConnectState::DISCONNECTED):
            realConnectionState = BluetoothConnectionState::DISCONNECTED;
            break;
        default:
            realConnectionState = -1;
    }
    return realConnectionState;
}

ErrCode GetBluetoothInfoPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("GetBluetoothInfoPlugin OnGetPolicy.");
    std::string name = Bluetooth::BluetoothHost::GetDefaultHost().GetLocalName();
    int32_t state = Bluetooth::BluetoothHost::GetDefaultHost().GetBtState();
    int32_t connectionState = Bluetooth::BluetoothHost::GetDefaultHost().GetBtConnectionState();
    int32_t realState = TransformBluetoothState(state);
    int32_t realConnectionState = TransformBluetoothConnectionState(connectionState);
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