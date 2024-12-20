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

#ifndef SERVICES_EDM_INCLUDE_UTILS_ARRAY_USB_DEVICE_TYPE_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_ARRAY_USB_DEVICE_TYPE_SERIALIZER_H

#include "ipolicy_serializer.h"
#include "singleton.h"
#include "usb_interface_type.h"

namespace OHOS {
namespace EDM {
/*
 * Policy data serializer of type std::vector<USB::UsbDeviceType>.
 */
class ArrayUsbDeviceTypeSerializer : public IPolicySerializer<std::vector<USB::UsbDeviceType>>,
    public DelayedSingleton<ArrayUsbDeviceTypeSerializer> {
public:
    std::vector<USB::UsbDeviceType> SetUnionPolicyData(std::vector<USB::UsbDeviceType> &data,
        std::vector<USB::UsbDeviceType> &currentData);
    std::vector<USB::UsbDeviceType> SetDifferencePolicyData(std::vector<USB::UsbDeviceType> &data,
        std::vector<USB::UsbDeviceType> &currentData);

    bool Deserialize(const std::string &jsonString, std::vector<USB::UsbDeviceType> &dataObj) override;
    bool Serialize(const std::vector<USB::UsbDeviceType> &dataObj, std::string &jsonString) override;
    bool GetPolicy(MessageParcel &data, std::vector<USB::UsbDeviceType> &result) override;
    bool WritePolicy(MessageParcel &reply, std::vector<USB::UsbDeviceType> &result) override;
    bool MergePolicy(std::vector<std::vector<USB::UsbDeviceType>> &data,
        std::vector<USB::UsbDeviceType> &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_UTILS_ARRAY_USB_DEVICE_TYPE_SERIALIZER_H
