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
#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "os_account_manager.h"
#include "parameters.h"
#include "usb_interface_type.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    DisallowedUsbStorageDeviceWritePlugin::GetPlugin());
const std::string CONSTRAINT_USB_STORAGE_DEVICE_WRITE = "constraint.usb.storageDevice.write"; // 存储类型的USB设备只读策略
const int32_t USB_DEVICE_TYPE_BASE_CLASS_STORAGE = 8;

void DisallowedUsbStorageDeviceWritePlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowedUsbStorageDeviceWritePlugin, bool>> ptr)
{
    EDMLOGI("DisallowedUsbStorageDeviceWritePlugin InitPlugin...");
    ptr->InitAttribute(
        EdmInterfaceCode::DISALLOWED_USB_STORAGE_DEVICE_WRITE,
        PolicyName::POLICY_DISALLOWED_USB_STORAGE_DEVICE_WRITE,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedUsbStorageDeviceWritePlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowedUsbStorageDeviceWritePlugin::OnAdminRemove);
}

ErrCode DisallowedUsbStorageDeviceWritePlugin::OnSetPolicy(bool &data, bool &currentData, bool &mergeData,
    int32_t userId)
{
    EDMLOGI("DisallowedUsbStorageDeviceWritePlugin::OnSetPolicy, data: %{public}d, currentData: %{public}d, "
            "mergeData: %{public}d", data, currentData, mergeData);
    std::string value = system::GetParameter(
        EdmConstants::CONST_ENTERPRISE_EXTERNAL_STORAGE_DEVICE_MANAGE_ENABLE, "false");
    if (value == "false") {
        EDMLOGE("DisallowedUsbStorageDeviceWritePlugin::OnSetPolicy failed, interface unsupported");
        return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
    }
    bool isConflict = false;
    if (FAILED(HasConflictPolicy(isConflict))) {
        EDMLOGE("DisallowedUsbStorageDeviceWritePlugin::OnSetPolicy, HasConflictPolicy failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (isConflict) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }

    if (mergeData) {
        currentData = data;
        return ERR_OK;
    }
    ErrCode ret = SetUsbStorageDeviceWritePolicy(data, userId);
    EDMLOGI("DisallowedUsbStorageDeviceWritePlugin::OnSetPolicy, "
            "SetUsbStorageDeviceWritePolicy ret: %{public}d", ret);
    if (FAILED(ret)) {
        EDMLOGE("DisallowedUsbStorageDeviceWritePlugin::OnSetPolicy, SetUsbStorageDeviceWritePolicy failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = data;
    mergeData = data;
    return ERR_OK;
}

ErrCode DisallowedUsbStorageDeviceWritePlugin::OnAdminRemove(const std::string &adminName, bool &data,
    bool &mergeData, int32_t userId)
{
    EDMLOGI("DisallowedUsbStorageDeviceWritePlugin::OnAdminRemove, adminName: %{public}s, data: %{public}d, "
            "mergeData: %{public}d", adminName.c_str(), data, mergeData);
    // admin 移除时，综合策略为只读，则最终策略不变，仍未只读
    if (mergeData) {
        return ERR_OK;
    }
    // admin 移除时，综合策略为读写，且移除的策略为只读，则更新策略为读写
    if (data) {
        ErrCode ret = SetUsbStorageDeviceWritePolicy(false, userId);
        EDMLOGI("DisallowedUsbStorageDeviceWritePlugin::OnAdminRemove, "
                "SetUsbStorageDeviceWritePolicy ret: %{public}d", ret);
        if (FAILED(ret)) {
            EDMLOGE("DisallowedUsbStorageDeviceWritePlugin::OnAdminRemove, SetUsbStorageDeviceWritePolicy failed");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

ErrCode DisallowedUsbStorageDeviceWritePlugin::SetUsbStorageDeviceWritePolicy(bool policy, int32_t userId)
{
    EDMLOGI("DisallowedUsbStorageDeviceWritePlugin::SetUsbStorageDeviceWritePolicy, "
            "policy: %{public}d", policy);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_USB_STORAGE_DEVICE_WRITE);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(constraints, policy, userId,
        EdmConstants::DEFAULT_USER_ID, true);
    EDMLOGI("DisallowedUsbStorageDeviceWritePlugin::SetUsbStorageDeviceWritePolicy, "
            "SetSpecificOsAccountConstraints ret: %{public}d", ret);
    return ret;
}

ErrCode DisallowedUsbStorageDeviceWritePlugin::HasConflictPolicy(bool &isConflict)
{
    EDMLOGI("DisallowedUsbStorageDeviceWritePlugin::HasConflictPolicy enter");
    auto policyManager = IPolicyManager::GetInstance();
    std::string disableUsb;
    policyManager->GetPolicy("", PolicyName::POLICY_DISABLE_USB, disableUsb);
    if (disableUsb == "true") {
        EDMLOGE("DisallowedUsbStorageDeviceWritePlugin::HasConflictPolicy, policy conflict! disableUsb: %{public}s",
            disableUsb.c_str());
        isConflict = true;
        return ERR_OK;
    }
    std::string usbStoragePolicy;
    policyManager->GetPolicy("", PolicyName::POLICY_USB_READ_ONLY, usbStoragePolicy);
    if (usbStoragePolicy == std::to_string(EdmConstants::STORAGE_USB_POLICY_DISABLED) ||
        usbStoragePolicy == std::to_string(EdmConstants::STORAGE_USB_POLICY_READ_ONLY)) {
        EDMLOGE("DisallowedUsbStorageDeviceWritePlugin::HasConflictPolicy, policy conflict! "
                "usbStoragePolicy: %{public}s", usbStoragePolicy.c_str());
        isConflict = true;
        return ERR_OK;
    }
    std::string disallowUsbDevicePolicy;
    policyManager->GetPolicy("", PolicyName::POLICY_DISALLOWED_USB_DEVICES, disallowUsbDevicePolicy);
    std::vector<USB::UsbDeviceType> usbDeviceTypes;
    if (!ArrayUsbDeviceTypeSerializer::GetInstance()->Deserialize(disallowUsbDevicePolicy, usbDeviceTypes)) {
        EDMLOGE("DisallowedUsbStorageDeviceWritePlugin::Deserialize failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    bool isStorageUsbDisallowed = std::find_if(usbDeviceTypes.begin(), usbDeviceTypes.end(),
        [&](USB::UsbDeviceType disallowedType) {
            return disallowedType.baseClass == USB_DEVICE_TYPE_BASE_CLASS_STORAGE;
        }) != usbDeviceTypes.end();
    if (isStorageUsbDisallowed) {
        EDMLOGE("DisallowedUsbStorageDeviceWritePlugin::HasConflictPolicy, policy conflict! "
                "isStorageUsbDisallowed: %{public}d", isStorageUsbDisallowed);
        isConflict = true;
        return ERR_OK;
    }

    EDMLOGI("DisallowedUsbStorageDeviceWritePlugin::HasConflictPolicy end, no conflict");
    isConflict = false;
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
