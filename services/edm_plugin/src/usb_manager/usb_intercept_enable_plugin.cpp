/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "usb_intercept_enable_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iadmin_manager.h"
#include "imdm_event_relayer.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<UsbInterceptEnablePlugin>());

UsbInterceptEnablePlugin::UsbInterceptEnablePlugin()
{
    EDMLOGI("UsbInterceptEnablePlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::USB_INTERCEPT_ENABLE;
    policyName_ = PolicyName::POLICY_USB_INTERCEPT_ENABLE;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB, IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
    // 需求文档：persist.edm.usb.intercept_enable = "true"/"false"
    persistParam_ = EdmConstants::PARAM_EDM_USB_INTERCEPT_ENABLE;
}

ErrCode UsbInterceptEnablePlugin::CheckConflictPolicy(int32_t userId)
{
    ErrCode ret = CheckConflictWithUsbRestrictionPolicies();
    if (FAILED(ret)) {
        return ret;
    }
    return CheckConflictWithUsbDeviceListPolicies();
}

ErrCode UsbInterceptEnablePlugin::CheckConflictWithUsbRestrictionPolicies()
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string disableUsb;
    policyManager->GetPolicy("", PolicyName::POLICY_DISABLE_USB, disableUsb);
    if (disableUsb == "true") {
        EDMLOGE("UsbInterceptEnablePlugin POLICY CONFLICT! Usb is disabled.");
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    std::string disableUsbSerial;
    policyManager->GetPolicy("", PolicyName::POLICY_DISALLOW_USB_SERIAL, disableUsbSerial);
    if (disableUsbSerial == "true") {
        EDMLOGE("UsbInterceptEnablePlugin POLICY CONFLICT! Usb serial is disabled.");
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    std::string usbStoragePolicy;
    policyManager->GetPolicy("", PolicyName::POLICY_USB_READ_ONLY, usbStoragePolicy);
    if (usbStoragePolicy == std::to_string(EdmConstants::STORAGE_USB_POLICY_DISABLED)) {
        EDMLOGE("UsbInterceptEnablePlugin POLICY CONFLICT! usbStoragePolicy disabled: %{public}s",
            usbStoragePolicy.c_str());
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    return ERR_OK;
}

ErrCode UsbInterceptEnablePlugin::CheckConflictWithUsbDeviceListPolicies()
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string disallowUsbDevice;
    policyManager->GetPolicy("", PolicyName::POLICY_DISALLOWED_USB_DEVICES, disallowUsbDevice);
    if (!disallowUsbDevice.empty()) {
        EDMLOGE("UsbInterceptEnablePlugin POLICY CONFLICT! disallowUsbDevice: %{public}s",
            disallowUsbDevice.c_str());
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    std::string disallowPermissiveUsbDevice;
    policyManager->GetPolicy("", PolicyName::POLICY_DISALLOWED_PERMISSIVE_USB_DEVICES,
        disallowPermissiveUsbDevice);
    if (!disallowPermissiveUsbDevice.empty()) {
        EDMLOGE("UsbInterceptEnablePlugin POLICY CONFLICT! disallowPermissiveUsbDevice: %{public}s",
            disallowPermissiveUsbDevice.c_str());
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    std::string allowUsbDevice;
    policyManager->GetPolicy("", PolicyName::POLICY_ALLOWED_USB_DEVICES, allowUsbDevice);
    if (!allowUsbDevice.empty()) {
        EDMLOGE("UsbInterceptEnablePlugin POLICY CONFLICT! allowedUsbDevice: %{public}s",
            allowUsbDevice.c_str());
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    return ERR_OK;
}

void UsbInterceptEnablePlugin::OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName,
    bool isGlobalChanged, int32_t userId)
{
    EDMLOGI("UsbInterceptEnablePlugin::OnHandlePolicyDone admin: %{public}s", adminName.c_str());
    std::string policyValue;
    IPolicyManager::GetInstance()->GetPolicy(adminName, policyName_, policyValue, userId);
    bool enabled = policyValue == EdmConstants::CONST_TRUE;
    std::vector<uint32_t> events = {static_cast<uint32_t>(ManagedEvent::USB_DEVICE_ADDED)};
    if (enabled) {
        IAdminManager::GetInstance()->SaveSubscribeEvents(events, adminName, userId);
        IMdmEventRelayer::GetInstance()->OnAdminSubscribe(adminName, userId,
            ManagedEvent::USB_DEVICE_ADDED);
    } else {
        IAdminManager::GetInstance()->RemoveSubscribeEvents(events, adminName, userId);
        IMdmEventRelayer::GetInstance()->OnAdminUnsubscribe(adminName, userId,
            ManagedEvent::USB_DEVICE_ADDED);
    }
}

void UsbInterceptEnablePlugin::OnAdminRemoveDone(const std::string &adminName,
    const std::string &currentJsonData, int32_t userId)
{
    EDMLOGI("UsbInterceptEnablePlugin::OnAdminRemoveDone admin: %{public}s", adminName.c_str());
    std::vector<uint32_t> events = {static_cast<uint32_t>(ManagedEvent::USB_DEVICE_ADDED)};
    IAdminManager::GetInstance()->RemoveSubscribeEvents(events, adminName, userId);
    IMdmEventRelayer::GetInstance()->OnAdminUnsubscribe(adminName, userId,
        ManagedEvent::USB_DEVICE_ADDED);
}
} // namespace EDM
} // namespace OHOS
