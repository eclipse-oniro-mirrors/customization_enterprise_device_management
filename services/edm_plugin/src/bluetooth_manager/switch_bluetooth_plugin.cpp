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

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iedm_bluetooth_manager.h"
#include "iplugin_manager.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<SwitchBluetoothPlugin>());
const std::string MDM_BLUETOOTH_PROP = "persist.edm.prohibit_bluetooth";
const std::string PARAM_FORCE_ENABLE_BLUETOOTH = "persist.edm.force_enable_bluetooth";

SwitchBluetoothPlugin::SwitchBluetoothPlugin()
{
    EDMLOGI("SwitchBluetoothPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::SWITCH_BLUETOOTH;
    policyName_ = "switch_bluetooth";
    permissionConfig_ = IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_BLUETOOTH,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode SwitchBluetoothPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    bool isOpen = data.ReadBool();
    if (system::GetBoolParameter(MDM_BLUETOOTH_PROP, false)) {
        EDMLOGE("SwitchBluetoothPlugin OnSetPolicy failed, because bluetooth disabled.");
        return EdmReturnErrCode::ENTERPRISE_POLICES_DENIED;
    }
    bool ret = false;
    if (isOpen) {
        system::SetParameter(PARAM_FORCE_ENABLE_BLUETOOTH, "false");
        ret = IEdmBluetoothManager::GetInstance()->EnableBle();
    } else {
        system::SetParameter(PARAM_FORCE_ENABLE_BLUETOOTH, "false");
        ret = IEdmBluetoothManager::GetInstance()->DisableBt();
    }
    if (!ret) {
        EDMLOGE("SwitchBluetoothPlugin:OnSetPolicy send request fail. %{public}d", ret);
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS