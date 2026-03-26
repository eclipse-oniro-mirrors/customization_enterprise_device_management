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
#include "switch_bluetooth_plugin.h"

#include "bluetooth_def.h"
#include "bluetooth_errorcode.h"
#include "bluetooth_host.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SwitchBluetoothPlugin::GetPlugin());
const std::string MDM_BLUETOOTH_PROP = "persist.edm.prohibit_bluetooth";

void SwitchBluetoothPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SwitchBluetoothPlugin, bool>> ptr)
{
    EDMLOGI("SwitchBluetoothPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::SWITCH_BLUETOOTH, "switch_bluetooth",
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SwitchBluetoothPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode SwitchBluetoothPlugin::OnSetPolicy(bool &isOpen)
{
    if (system::GetBoolParameter(MDM_BLUETOOTH_PROP, false)) {
        EDMLOGE("SwitchBluetoothPlugin OnSetPolicy failed, because bluetooth disabled.");
        return EdmReturnErrCode::ENTERPRISE_POLICES_DENIED;
    }
    int32_t ret = Bluetooth::BT_NO_ERROR;
    if (isOpen) {
        ret = Bluetooth::BluetoothHost::GetDefaultHost().EnableBle();
    } else {
        ret = Bluetooth::BluetoothHost::GetDefaultHost().DisableBt();
    }
    if (ret != Bluetooth::BT_NO_ERROR) {
        EDMLOGE("SwitchBluetoothPlugin:OnSetPolicy send request fail. %{public}d", ret);
    }
    return ERR_OK;
}

SwitchBluetoothPlugin::~SwitchBluetoothPlugin()
{
    Bluetooth::BluetoothHost::GetDefaultHost().Close();
}
} // namespace EDM
} // namespace OHOS