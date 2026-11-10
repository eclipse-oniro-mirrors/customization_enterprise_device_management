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

#include "usb_device_info_mapper.h"

namespace OHOS {
namespace EDM {
namespace {
USBInterfaceInfo ToKitInterface(const UsbFlatInterfaceInfo &flat)
{
    USBInterfaceInfo iface;
    iface.id = flat.interfaceId;
    iface.protocol = flat.protocol;
    iface.clazz = flat.interfaceClass;
    iface.subClass = flat.subClass;
    iface.name = "";
    iface.states = flat.enabled;
    return iface;
}

USBConfigurationInfo BuildSyntheticConfig(const UsbFlatDeviceInfo &flat)
{
    USBConfigurationInfo config;
    config.id = USB_SYNTHETIC_CONFIG_ID;
    config.name = "";
    config.states = flat.enabled;
    config.interfaces.reserve(flat.interfaces.size());
    for (const auto &flatIface : flat.interfaces) {
        config.interfaces.emplace_back(ToKitInterface(flatIface));
    }
    return config;
}
} // namespace

UsbDeviceInfo UsbDeviceInfoMapper::ToKitDeviceInfo(const UsbFlatDeviceInfo &flat)
{
    UsbDeviceInfo info;
    info.busNum = static_cast<int32_t>(flat.busNum);
    info.devAddress = static_cast<int32_t>(flat.devAddr);
    info.serial = flat.serial;
    info.name = "";
    info.manufacturerName = flat.manufacturerName;
    info.productName = flat.productName;
    info.version = "";
    info.vendorId = flat.vendorId;
    info.productId = flat.productId;
    info.clazz = flat.deviceClass;
    info.subClass = flat.subClass;
    info.protocol = flat.protocol;
    info.states = flat.enabled;
    info.configs = {BuildSyntheticConfig(flat)};
    return info;
}

void UsbDeviceInfoMapper::ToKitDeviceInfos(const std::vector<UsbFlatDeviceInfo> &flatList,
    std::vector<UsbDeviceInfo> &kitList)
{
    kitList.clear();
    kitList.reserve(flatList.size());
    for (const auto &flat : flatList) {
        kitList.emplace_back(ToKitDeviceInfo(flat));
    }
}

bool UsbDeviceInfoMapper::IsInterfaceAuthorize(const USBDeviceConfigInfo &config)
{
    return config.hasConfigId && config.hasInterfaceId;
}
} // namespace EDM
} // namespace OHOS
