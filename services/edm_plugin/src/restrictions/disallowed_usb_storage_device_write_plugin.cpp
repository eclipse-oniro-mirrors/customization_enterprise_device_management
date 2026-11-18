/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "disallowed_usb_storage_device_write_plugin.h"

#include <ipc_skeleton.h>
#include "array_usb_device_type_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "os_account_manager.h"
#include "parameters.h"
#include "usb_interface_type.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<DisallowedUsbStorageDeviceWritePlugin>());
const std::string CONSTRAINT_USB_STORAGE_DEVICE_WRITE = "constraint.usb.storageDevice.write"; // 存储类型的USB设备只读策略
const int32_t USB_DEVICE_TYPE_BASE_CLASS_STORAGE = 8;

DisallowedUsbStorageDeviceWritePlugin::DisallowedUsbStorageDeviceWritePlugin()
{
    EDMLOGI("DisallowedUsbStorageDeviceWritePlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOWED_USB_STORAGE_DEVICE_WRITE;
    policyName_ = PolicyName::POLICY_DISALLOWED_USB_STORAGE_DEVICE_WRITE;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode DisallowedUsbStorageDeviceWritePlugin::SetOtherModulePolicy(bool policy, int32_t userId)
{
    EDMLOGI("DisallowedUsbStorageDeviceWritePlugin::SetUsbStorageDeviceWritePolicy, "
            "policy: %{public}d", policy);
    std::string value = system::GetParameter(
        EdmConstants::CONST_ENTERPRISE_EXTERNAL_STORAGE_DEVICE_MANAGE_ENABLE, "false");
    if (value == "false") {
        EDMLOGE("DisallowedUsbStorageDeviceWritePlugin::OnSetPolicy failed, interface unsupported");
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_USB_STORAGE_DEVICE_WRITE);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(constraints, policy, userId,
        EdmConstants::DEFAULT_USER_ID, true);
    if (FAILED(ret)) {
        EDMLOGE("DisallowedUsbStorageDeviceWritePlugin::OnSetPolicy, SetUsbStorageDeviceWritePolicy failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode DisallowedUsbStorageDeviceWritePlugin::CheckConflictPolicy(int32_t userId)
{
    EDMLOGI("DisallowedUsbStorageDeviceWritePlugin::HasConflictPolicy enter");
    auto policyManager = IPolicyManager::GetInstance();
    std::string disableUsb;
    policyManager->GetPolicy("", PolicyName::POLICY_DISABLE_USB, disableUsb);
    if (disableUsb == "true") {
        EDMLOGE("DisallowedUsbStorageDeviceWritePlugin::HasConflictPolicy, policy conflict! disableUsb: %{public}s",
            disableUsb.c_str());
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    std::string usbStoragePolicy;
    policyManager->GetPolicy("", PolicyName::POLICY_USB_READ_ONLY, usbStoragePolicy);
    if (usbStoragePolicy == std::to_string(EdmConstants::STORAGE_USB_POLICY_DISABLED) ||
        usbStoragePolicy == std::to_string(EdmConstants::STORAGE_USB_POLICY_READ_ONLY)) {
        EDMLOGE("DisallowedUsbStorageDeviceWritePlugin::HasConflictPolicy, policy conflict! "
                "usbStoragePolicy: %{public}s", usbStoragePolicy.c_str());
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    std::string disallowUsbDevicePolicy;
    policyManager->GetPolicy("", PolicyName::POLICY_DISALLOWED_USB_DEVICES, disallowUsbDevicePolicy);
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    if (!ArrayUsbDeviceTypeSerializer::GetInstance()->Deserialize(disallowUsbDevicePolicy, usbDeviceTypes)) {
        EDMLOGE("DisallowedUsbStorageDeviceWritePlugin::Deserialize failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string disallowPermissiveUsbDevicePolicy;
    policyManager->GetPolicy("", PolicyName::POLICY_DISALLOWED_PERMISSIVE_USB_DEVICES,
        disallowPermissiveUsbDevicePolicy);
    if (!disallowPermissiveUsbDevicePolicy.empty()) {
        EDMLOGE("DisallowedUsbStorageDeviceWritePlugin::HasConflictPolicy, policy conflict! "
            "disallowPermissiveUsbDevicePolicy: %{public}s", disallowPermissiveUsbDevicePolicy.c_str());
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    bool isStorageUsbDisallowed = std::find_if(usbDeviceTypes.begin(), usbDeviceTypes.end(),
        [&](USB::UsbDeviceType disallowedType) {
            return disallowedType.baseClass == USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
        }) != usbDeviceTypes.end();
    if (isStorageUsbDisallowed) {
        EDMLOGE("DisallowedUsbStorageDeviceWritePlugin::HasConflictPolicy, policy conflict! "
                "isStorageUsbDisallowed: %{public}d", isStorageUsbDisallowed);
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }

    EDMLOGI("DisallowedUsbStorageDeviceWritePlugin::HasConflictPolicy end, no conflict");
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
