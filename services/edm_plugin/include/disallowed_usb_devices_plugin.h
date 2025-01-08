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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_DISALLOWED_USB_DEVICES_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_DISALLOWED_USB_DEVICES_PLUGIN_H

#include "plugin_singleton.h"
#include "usb_interface_type.h"

namespace OHOS {
namespace EDM {
class DisallowedUsbDevicesPlugin : public PluginSingleton<DisallowedUsbDevicesPlugin, std::vector<USB::UsbDeviceType>> {
public:
    void InitPlugin(std::shared_ptr<IPluginTemplate<DisallowedUsbDevicesPlugin,
        std::vector<USB::UsbDeviceType>>> ptr) override;
    ErrCode OnSetPolicy(std::vector<USB::UsbDeviceType> &data, std::vector<USB::UsbDeviceType> &currentData,
        std::vector<USB::UsbDeviceType> &mergeData, int32_t userId);
    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;
    ErrCode OnRemovePolicy(std::vector<USB::UsbDeviceType> &data, std::vector<USB::UsbDeviceType> &currentData,
        std::vector<USB::UsbDeviceType> &mergeData, int32_t userId);
    ErrCode OnAdminRemove(const std::string &adminName, std::vector<USB::UsbDeviceType> &data,
        std::vector<USB::UsbDeviceType> &mergeData, int32_t userId);

private:
    bool HasConflictPolicy();
    void CombineDataWithStorageAccessPolicy(std::vector<USB::UsbDeviceType> policyData,
        std::vector<USB::UsbDeviceType> &combineData);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_DISALLOWED_USB_DEVICES_PLUGIN_H
