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

#include "disable_bluetooth_plugin.h"

#include "bluetooth_def.h"
#include "bluetooth_errorcode.h"
#include "bluetooth_host.h"
#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableBluetoothPlugin::GetPlugin());

void DisableBluetoothPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableBluetoothPlugin, bool>> ptr)
{
    EDMLOGI("DisableBluetoothPlugin InitPlugin...");
    std::map<std::string, std::map<IPlugin::PermissionType, std::string>> tagPermissions;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag11;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag12;
    typePermissionsForTag11.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        "ohos.permission.ENTERPRISE_MANAGE_BLUETOOTH");
    typePermissionsForTag12.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS");
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_11, typePermissionsForTag11);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_12, typePermissionsForTag12);
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(tagPermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_BLUETOOTH, "disabled_bluetooth", config, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableBluetoothPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableBluetoothPlugin::OnAdminRemove);
    persistParam_ = "persist.edm.prohibit_bluetooth";
}

ErrCode DisableBluetoothPlugin::SetOtherModulePolicy(bool data)
{
    if (data && Bluetooth::BluetoothHost::GetDefaultHost().IsBrEnabled() &&
        Bluetooth::BluetoothHost::GetDefaultHost().DisableBt() != Bluetooth::BT_NO_ERROR) {
        EDMLOGW("DisableBluetoothPlugin close bluetooth failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
