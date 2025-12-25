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

#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"
 
namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowUsbSerialPlugin::GetPlugin());
 
void DisallowUsbSerialPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisallowUsbSerialPlugin, bool>>
    ptr)
{
    EDMLOGI("DisallowUsbSerialPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOW_USB_SERIAL, PolicyName::POLICY_DISALLOW_USB_SERIAL,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowUsbSerialPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowUsbSerialPlugin::OnAdminRemove);
}
 
ErrCode DisallowUsbSerialPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    if (data && HasConflictPolicy()) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }

    const char* value = data ? "1" : "0";
    if (!system::SetParameter("persist.edm.usb_serial_disable", value)) {
        EDMLOGE("set disallow usb serial: %{public}s failed.", value);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode DisallowUsbSerialPlugin::RemoveOtherModulePolicy(int32_t userId)
{
    if (!system::SetParameter("persist.edm.usb_serial_disable", "0")) {
        EDMLOGE("set disallow usb serial false failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

bool DisallowUsbSerialPlugin::HasConflictPolicy()
{
    auto policyManager = IPolicyManager::GetInstance();
    std::string disableUsb;
    policyManager->GetPolicy("", PolicyName::POLICY_DISABLE_USB, disableUsb);
    if (disableUsb == "true") {
        EDMLOGE("DisallowUsbSerialPlugin policy conflict! Usb is disabled.");
        return true;
    }
    std::string allowUsbDevice;
    policyManager->GetPolicy("", PolicyName::POLICY_ALLOWED_USB_DEVICES, allowUsbDevice);
    if (!allowUsbDevice.empty()) {
        EDMLOGE("DisallowUsbSerialPlugin policy conflict! AllowedUsbDevice: %{public}s", allowUsbDevice.c_str());
        return true;
    }
    return false;
}
} // namespace EDM
} // namespace OHOS