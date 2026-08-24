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

#ifndef INTERFACES_INNER_API_USB_MANAGER_INCLUDE_ARRAY_ODD_BURN_USB_DEVICE_SERIALIZER_H
#define INTERFACES_INNER_API_USB_MANAGER_INCLUDE_ARRAY_ODD_BURN_USB_DEVICE_SERIALIZER_H

#include "ipolicy_serializer.h"
#include "odd_burn_usb_device.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
class ArrayOddBurnUsbDeviceSerializer : public IPolicySerializer<std::vector<OddBurnUsbDevice>>,
    public DelayedSingleton<ArrayOddBurnUsbDeviceSerializer> {
public:
    std::vector<OddBurnUsbDevice> SetUnionPolicyData(std::vector<OddBurnUsbDevice> &data,
        std::vector<OddBurnUsbDevice> &currentData);
    std::vector<OddBurnUsbDevice> SetDifferencePolicyData(std::vector<OddBurnUsbDevice> &data,
        std::vector<OddBurnUsbDevice> &currentData);
    bool Deserialize(const std::string &jsonString, std::vector<OddBurnUsbDevice> &dataObj) override;
    bool Serialize(const std::vector<OddBurnUsbDevice> &dataObj, std::string &jsonString) override;
    bool GetPolicy(MessageParcel &data, std::vector<OddBurnUsbDevice> &result) override;
    bool WritePolicy(MessageParcel &reply, std::vector<OddBurnUsbDevice> &result) override;
    bool MergePolicy(std::vector<std::vector<OddBurnUsbDevice>> &data,
        std::vector<OddBurnUsbDevice> &result) override;

    bool WriteRawDataToParcel(MessageParcel &parcel, const std::vector<OddBurnUsbDevice> &devices);
    bool ReadRawDataFromParcel(MessageParcel &parcel, std::vector<OddBurnUsbDevice> &devices);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_USB_MANAGER_INCLUDE_ARRAY_ODD_BURN_USB_DEVICE_SERIALIZER_H
