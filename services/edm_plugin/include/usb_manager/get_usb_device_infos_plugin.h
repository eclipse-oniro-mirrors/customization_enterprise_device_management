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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_USB_MANAGER_GET_USB_DEVICE_INFOS_PLUGIN_H
#define SERVICES_EDM_PLUGIN_INCLUDE_USB_MANAGER_GET_USB_DEVICE_INFOS_PLUGIN_H

#include <vector>

#include "iplugin.h"
#include "usb_device_info.h"
#include "usb_srv_client.h"

namespace OHOS {
namespace EDM {
class GetUsbDeviceInfosPlugin : public IPlugin {
public:
    GetUsbDeviceInfosPlugin();

    ErrCode OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply, int32_t userId) override;

private:
    ErrCode QueryUsbDeviceInfos(std::vector<UsbDeviceInfo> &infos);
    UsbDeviceInfo ToKitDeviceInfo(const USB::UsbDeviceInfo &usbInfo);
    USBInterfaceInfo ToKitInterfaceInfo(const USB::UsbInterfaceInfo &usbIface);
    USBConfigurationInfo BuildSyntheticConfig(const USB::UsbDeviceInfo &usbInfo);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_USB_MANAGER_GET_USB_DEVICE_INFOS_PLUGIN_H
