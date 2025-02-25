/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "disable_usb_plugin.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_utils.h"
#include "usb_policy_utils.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableUsbPlugin::GetPlugin());

void DisableUsbPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableUsbPlugin, bool>> ptr)
{
    EDMLOGI("DisableUsbPlugin InitPlugin...");
    std::map<std::string, std::map<IPlugin::PermissionType, std::string>> tagPermissions;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag11;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag12;
    typePermissionsForTag11.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB);
    typePermissionsForTag12.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    typePermissionsForTag12.emplace(IPlugin::PermissionType::BYOD_DEVICE_ADMIN,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_11, typePermissionsForTag11);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_12, typePermissionsForTag12);

    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(tagPermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_USB, "disable_usb", config, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableUsbPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableUsbPlugin::OnAdminRemove);
}

ErrCode DisableUsbPlugin::SetOtherModulePolicy(bool data)
{
    EDMLOGI("DisableUsbPlugin OnSetPolicy...disable = %{public}d", data);
    if (data && HasConflictPolicy()) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    if (FAILED(UsbPolicyUtils::SetUsbDisabled(data))) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

bool DisableUsbPlugin::HasConflictPolicy()
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string allowUsbDevice;
    policyManager->GetPolicy("", "allowed_usb_devices", allowUsbDevice);
    if (!allowUsbDevice.empty()) {
        EDMLOGE("DisableUsbPlugin POLICY CONFLICT! allowedUsbDevice: %{public}s", allowUsbDevice.c_str());
        return true;
    }
    std::string disallowUsbDevice;
    policyManager->GetPolicy("", "disallowed_usb_devices", disallowUsbDevice);
    if (!disallowUsbDevice.empty()) {
        EDMLOGE("DisableUsbPlugin POLICY CONFLICT! disallowUsbDevice: %{public}s", disallowUsbDevice.c_str());
        return true;
    }
    std::string usbStoragePolicy;
    policyManager->GetPolicy("", "usb_read_only", usbStoragePolicy);
    if (usbStoragePolicy == std::to_string(EdmConstants::STORAGE_USB_POLICY_DISABLED) ||
        usbStoragePolicy == std::to_string(EdmConstants::STORAGE_USB_POLICY_READ_ONLY)) {
        EDMLOGE("DisableUsbPlugin POLICY CONFLICT! usbStoragePolicy: %{public}s", usbStoragePolicy.c_str());
        return true;
    }
    return false;
}

ErrCode DisableUsbPlugin::RemoveOtherModulePolicy()
{
    return UsbPolicyUtils::SetUsbDisabled(true);
}
} // namespace EDM
} // namespace OHOS
