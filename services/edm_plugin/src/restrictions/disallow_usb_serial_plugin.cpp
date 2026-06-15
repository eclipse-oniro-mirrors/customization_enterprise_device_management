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
#include "disallow_usb_serial_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
 
namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisallowUsbSerialPlugin>());
 
DisallowUsbSerialPlugin::DisallowUsbSerialPlugin()
{
    EDMLOGI("DisallowUsbSerialPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOW_USB_SERIAL;
    policyName_ = PolicyName::POLICY_DISALLOW_USB_SERIAL;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
}
 
ErrCode DisallowUsbSerialPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    const char* value = data ? "1" : "0";
    if (!system::SetParameter("persist.edm.usb_serial_disable", value)) {
        EDMLOGE("set disallow usb serial: %{public}s failed.", value);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode DisallowUsbSerialPlugin::CheckConflictPolicy(int32_t userId)
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string disableUsb;
    policyManager->GetPolicy("", PolicyName::POLICY_DISABLE_USB, disableUsb);
    if (disableUsb == "true") {
        EDMLOGE("DisallowUsbSerialPlugin policy conflict! Usb is disabled.");
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    std::string allowUsbDevice;
    policyManager->GetPolicy("", PolicyName::POLICY_ALLOWED_USB_DEVICES, allowUsbDevice);
    if (!allowUsbDevice.empty()) {
        EDMLOGE("DisallowUsbSerialPlugin policy conflict! AllowedUsbDevice: %{public}s", allowUsbDevice.c_str());
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS