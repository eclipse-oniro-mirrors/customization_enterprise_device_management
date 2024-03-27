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

#ifndef INTERFACES_INNER_API_INCLUDE_USB_DEVICE_ID_H
#define INTERFACES_INNER_API_INCLUDE_USB_DEVICE_ID_H

#include <string>
#include "message_parcel.h"

namespace OHOS {
namespace EDM {
class UsbDeviceId {
public:
    bool Marshalling(MessageParcel &parcel) const;
    static bool Unmarshalling(MessageParcel &parcel, UsbDeviceId &usbDeviceId);

    void SetVendorId(int32_t vendorId);
    void SetProductId(int32_t productId);

    [[nodiscard]] int32_t GetVendorId() const;
    [[nodiscard]] int32_t GetProductId() const;

private:
    int32_t vendorId_ = -1;
    int32_t productId_ = -1;
};

struct Comp {
    bool operator()(const UsbDeviceId& id1, const UsbDeviceId& id2)
    {
        return (id1.GetVendorId() == id2.GetVendorId()) ?
            (id1.GetProductId() < id2.GetProductId()) : (id1.GetVendorId() < id2.GetVendorId());
    }
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_INCLUDE_USB_DEVICE_ID_H
