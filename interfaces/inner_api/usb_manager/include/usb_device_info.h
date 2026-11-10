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

#ifndef INTERFACES_INNER_API_USB_MANAGER_INCLUDE_USB_DEVICE_INFO_H
#define INTERFACES_INNER_API_USB_MANAGER_INCLUDE_USB_DEVICE_INFO_H

#include <cstdint>
#include <string>
#include <vector>

#include "message_parcel.h"

namespace OHOS {
namespace EDM {

struct USBInterfaceInfo {
    int32_t id = 0;
    int32_t protocol = 0;
    int32_t clazz = 0;
    int32_t subClass = 0;
    std::string name;
    bool isMount = false;

    bool Marshalling(Parcel &parcel) const;
    static bool Unmarshalling(Parcel &parcel, USBInterfaceInfo &info);
};

struct USBConfigurationInfo {
    int32_t id = 0;
    std::string name;
    bool isMount = false;
    std::vector<USBInterfaceInfo> interfaces;

    bool Marshalling(Parcel &parcel) const;
    static bool Unmarshalling(Parcel &parcel, USBConfigurationInfo &info);
};

struct USBDeviceConfigInfo {
    int32_t busNum = 0;
    int32_t devAddress = 0;
    bool hasConfigId = false;
    int32_t configId = 0;
    bool hasInterfaceId = false;
    int32_t interfaceId = 0;

    bool Marshalling(Parcel &parcel) const;
    static bool Unmarshalling(Parcel &parcel, USBDeviceConfigInfo &info);
};

class UsbDeviceInfo : public Parcelable {
public:
    UsbDeviceInfo() = default;
    ~UsbDeviceInfo() = default;

    bool Marshalling(Parcel &parcel) const override;
    static bool Unmarshalling(Parcel &parcel, UsbDeviceInfo &info);

    int32_t busNum = 0;
    int32_t devAddress = 0;
    std::string serial;
    std::string name;
    std::string manufacturerName;
    std::string productName;
    std::string version;
    int32_t vendorId = 0;
    int32_t productId = 0;
    int32_t clazz = 0;
    int32_t subClass = 0;
    int32_t protocol = 0;
    bool isMount = false;
    std::vector<USBConfigurationInfo> configs;
};

} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_USB_MANAGER_INCLUDE_USB_DEVICE_INFO_H
