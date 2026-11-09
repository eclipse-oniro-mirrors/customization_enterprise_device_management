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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_UTILS_USB_FLAT_DEVICE_INFO_H
#define SERVICES_EDM_PLUGIN_INCLUDE_UTILS_USB_FLAT_DEVICE_INFO_H

#include <cstdint>
#include <string>
#include <vector>

namespace OHOS {
namespace EDM {

/**
 * Local mirror of USB-side flat structs from busmanager_usb_manager PR #1458
 * (UsbServerTypes.idl UsbDeviceInfo / UsbInterfaceInfo).
 *
 * Field notes vs Kit UsbDeviceInfo:
 * - authorized ≡ Kit states
 * - deviceClass ≡ Kit clazz; interfaceClass ≡ Kit interface clazz
 * - devAddr ≡ Kit UsbDeviceInfo.devAddress / USBDeviceConfigInfo.devAddr
 * - deviceId / isHub / alternateSetting: Kit does not expose
 * - USB has no configs[] / name / version: Kit wraps interfaces in one config
 */
struct UsbFlatInterfaceInfo {
    int32_t interfaceId = 0;
    int32_t interfaceClass = 0;
    int32_t subClass = 0;
    int32_t protocol = 0;
    int32_t alternateSetting = 0; // Kit ignores
    bool authorized = false;      // ≡ Kit states
};

struct UsbFlatDeviceInfo {
    std::string deviceId; // Kit ignores
    uint8_t busNum = 0;
    uint8_t devAddr = 0;
    int32_t vendorId = 0;
    int32_t productId = 0;
    int32_t deviceClass = 0;
    int32_t subClass = 0;
    int32_t protocol = 0;
    std::string serial;
    std::string manufacturerName;
    std::string productName;
    bool isHub = false;      // Kit ignores; hub policy is USB-side
    bool authorized = false; // ≡ Kit states
    std::vector<UsbFlatInterfaceInfo> interfaces;
};

// Synthetic configs[].id when wrapping flat interfaces (USB flat model has no configId).
// MDM must pass this value back in setUsbDeviceStates; confirm with USB on联调.
constexpr int32_t USB_SYNTHETIC_CONFIG_ID = 1;

} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_UTILS_USB_FLAT_DEVICE_INFO_H
