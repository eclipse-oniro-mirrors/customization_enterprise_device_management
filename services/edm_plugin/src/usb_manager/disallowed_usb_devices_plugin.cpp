/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "disallowed_usb_devices_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "usb_policy_utils.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowedUsbDevicesPlugin::GetPlugin());

void DisallowedUsbDevicesPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowedUsbDevicesPlugin, std::vector<USB::UsbDeviceType>>> ptr)
{
    EDMLOGI("DisallowedUsbDevicesPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_USB_DEVICES, PolicyName::POLICY_DISALLOWED_USB_DEVICES,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_USB, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(ArrayUsbDeviceTypeSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedUsbDevicesPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnHandlePolicyListener(&DisallowedUsbDevicesPlugin::OnRemovePolicy, FuncOperateType::REMOVE);
    ptr->SetOnAdminRemoveListener(&DisallowedUsbDevicesPlugin::OnAdminRemove);
    ptr->SetOtherServiceStartListener(&DisallowedUsbDevicesPlugin::OnOtherServiceStart);
}

ErrCode DisallowedUsbDevicesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    return DisallowedUsbDevicesPluginBase::OnBaseGetPolicy(policyData, data, reply, userId);
}

const char* DisallowedUsbDevicesPlugin::GetPolicyName() const
{
    return PolicyName::POLICY_DISALLOWED_USB_DEVICES;
}

uint32_t DisallowedUsbDevicesPlugin::GetDisallowedUsbDevicesTypeMaxSize() const
{
    return EdmConstants::DISALLOWED_USB_DEVICES_TYPES_MAX_SIZE;
}

const char* DisallowedUsbDevicesPlugin::GetConflictPolicyName() const
{
    return PolicyName::POLICY_DISALLOWED_PERMISSIVE_USB_DEVICES;
}

ErrCode DisallowedUsbDevicesPlugin::SetDisallowedDevices(std::vector<USB::UsbDeviceType> &data)
{
    return UsbPolicyUtils::SetDisallowedUsbDevices(data);
}

std::string DisallowedUsbDevicesPlugin::GetPluginName() const
{
    return "DisallowedUsbDevicesPlugin";
}

std::shared_ptr<ArrayUsbDeviceTypeSerializerBase> DisallowedUsbDevicesPlugin::GetSerializer()
{
    return ArrayUsbDeviceTypeSerializer::GetInstance();
}
} // namespace EDM
} // namespace OHOS
