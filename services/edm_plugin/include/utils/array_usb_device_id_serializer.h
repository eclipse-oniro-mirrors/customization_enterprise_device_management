/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef SERVICES_EDM_PLUGIN_INCLUDE_UTILS_ARRAY_USB_DEVICE_ID_SERIALIZER_H
#define SERVICES_EDM_PLUGIN_INCLUDE_UTILS_ARRAY_USB_DEVICE_ID_SERIALIZER_H

#include "ipolicy_serializer.h"
#include "singleton.h"
#include "usb_device_id.h"

namespace OHOS {
namespace EDM {
/*
 * Policy data serializer of type std::vector<UsbDeviceId>.
 */
class ArrayUsbDeviceIdSerializer : public IPolicySerializer<std::vector<UsbDeviceId>>,
    public DelayedSingleton<ArrayUsbDeviceIdSerializer> {
public:
    std::vector<UsbDeviceId> SetUnionPolicyData(std::vector<UsbDeviceId> &data, std::vector<UsbDeviceId> &currentData);
    std::vector<UsbDeviceId> SetDifferencePolicyData(std::vector<UsbDeviceId> &data,
        std::vector<UsbDeviceId> &currentData);
    bool Deserialize(const std::string &jsonString, std::vector<UsbDeviceId> &dataObj) override;
    bool Serialize(const std::vector<UsbDeviceId> &dataObj, std::string &jsonString) override;
    bool GetPolicy(MessageParcel &data, std::vector<UsbDeviceId> &result) override;
    bool WritePolicy(MessageParcel &reply, std::vector<UsbDeviceId> &result) override;
    bool MergePolicy(std::vector<std::vector<UsbDeviceId>> &data, std::vector<UsbDeviceId> &result) override;
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_PLUGIN_INCLUDE_UTILS_ARRAY_USB_DEVICE_ID_SERIALIZER_H
