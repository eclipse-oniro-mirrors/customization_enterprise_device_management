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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_UTILS_USB_DEVICE_INFO_MAPPER_H
#define SERVICES_EDM_PLUGIN_INCLUDE_UTILS_USB_DEVICE_INFO_MAPPER_H

#include <vector>

#include "usb_device_info.h"
#include "usb_flat_device_info.h"

namespace OHOS {
namespace EDM {
class UsbDeviceInfoMapper {
public:
    static UsbDeviceInfo ToKitDeviceInfo(const UsbFlatDeviceInfo &flat);
    static void ToKitDeviceInfos(const std::vector<UsbFlatDeviceInfo> &flatList,
        std::vector<UsbDeviceInfo> &kitList);

    // true = interface dimension (needs configId + interfaceId); false = device dimension
    static bool IsInterfaceAuthorize(const USBDeviceConfigInfo &config);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_UTILS_USB_DEVICE_INFO_MAPPER_H
