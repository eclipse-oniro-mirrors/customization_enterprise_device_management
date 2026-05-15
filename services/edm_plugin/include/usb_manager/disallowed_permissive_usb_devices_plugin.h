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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_DISALLOWED_PERMISSIVE_USB_DEVICES_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_DISALLOWED_PERMISSIVE_USB_DEVICES_PLUGIN_H

#include "array_permissive_usb_device_type_serializer.h"
#include "disallowed_usb_devices_plugin_base.h"
#include "plugin_singleton.h"
#include "usb_interface_type.h"

namespace OHOS {
namespace EDM {
class DisallowedPermissiveUsbDevicesPlugin : public PluginSingleton<DisallowedPermissiveUsbDevicesPlugin,
    std::vector<USB::UsbDeviceType>>, public DisallowedUsbDevicesPluginBase {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<DisallowedPermissiveUsbDevicesPlugin,
        std::vector<USB::UsbDeviceType>>> ptr) override;
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;

protected:
    const char* GetPolicyName() const override;
    uint32_t GetDisallowedUsbDevicesTypeMaxSize() const override;
    const char* GetConflictPolicyName() const override;
    ErrCode SetDisallowedDevices(std::vector<USB::UsbDeviceType> &data) override;
    std::string GetPluginName() const override;
    std::shared_ptr<ArrayUsbDeviceTypeSerializerBase> GetSerializer() override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_DISALLOWED_PERMISSIVE_USB_DEVICES_PLUGIN_H
