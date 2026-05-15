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

#include "disallowed_permissive_usb_devices_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "usb_policy_utils.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(DisallowedPermissiveUsbDevicesPlugin::GetPlugin());

void DisallowedPermissiveUsbDevicesPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowedPermissiveUsbDevicesPlugin, std::vector<USB::UsbDeviceType>>> ptr)
{
    EDMLOGI("DisallowedPermissiveUsbDevicesPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_PERMISSIVE_USB_DEVICES,
        PolicyName::POLICY_DISALLOWED_PERMISSIVE_USB_DEVICES,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayPermissiveUsbDeviceTypeSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedPermissiveUsbDevicesPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&DisallowedPermissiveUsbDevicesPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&DisallowedPermissiveUsbDevicesPlugin::OnAdminRemove);
    ptr->SetOtherServiceStartListener(&DisallowedPermissiveUsbDevicesPlugin::OnOtherServiceStart);
}

ErrCode DisallowedPermissiveUsbDevicesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    return DisallowedUsbDevicesPluginBase::OnBaseGetPolicy(policyData, data, reply, userId);
}

const char* DisallowedPermissiveUsbDevicesPlugin::GetPolicyName() const
{
    return PolicyName::POLICY_DISALLOWED_PERMISSIVE_USB_DEVICES;
}

uint32_t DisallowedPermissiveUsbDevicesPlugin::GetDisallowedUsbDevicesTypeMaxSize() const
{
    return EdmConstants::DISALLOWED_PERMISSIVE_USB_DEVICES_TYPES_MAX_SIZE;
}

const char* DisallowedPermissiveUsbDevicesPlugin::GetConflictPolicyName() const
{
    return PolicyName::POLICY_DISALLOWED_USB_DEVICES;
}

ErrCode DisallowedPermissiveUsbDevicesPlugin::SetDisallowedDevices(std::vector<USB::UsbDeviceType> &data)
{
    return UsbPolicyUtils::SetDisallowedPermissiveUsbDevices(data);
}

std::string DisallowedPermissiveUsbDevicesPlugin::GetPluginName() const
{
    return "DisallowedPermissiveUsbDevicesPlugin";
}

std::shared_ptr<ArrayUsbDeviceTypeSerializerBase> DisallowedPermissiveUsbDevicesPlugin::GetSerializer()
{
    return ArrayPermissiveUsbDeviceTypeSerializer::GetInstance();
}
} // namespace EDM
} // namespace OHOS
