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

#ifndef INTERFACES_INNER_API_INCLUDE_ODD_BURN_USB_DEVICE_H
#define INTERFACES_INNER_API_INCLUDE_ODD_BURN_USB_DEVICE_H

#include <string>
#include "message_parcel.h"

namespace OHOS {
namespace EDM {
class OddBurnUsbDevice {
public:
    bool Marshalling(MessageParcel &parcel) const;
    static bool Unmarshalling(MessageParcel &parcel, OddBurnUsbDevice &device);

    void SetVendorId(int32_t vendorId);
    void SetProductId(int32_t productId);
    void SetSerial(const std::string &serial);

    [[nodiscard]] int32_t GetVendorId() const;
    [[nodiscard]] int32_t GetProductId() const;
    [[nodiscard]] std::string GetSerial() const;

    bool operator==(const OddBurnUsbDevice &other) const
    {
        return vendorId_ == other.vendorId_ && productId_ == other.productId_ && serial_ == other.serial_;
    }

    bool operator<(const OddBurnUsbDevice &other) const
    {
        if (vendorId_ != other.vendorId_) {
            return vendorId_ < other.vendorId_;
        }
        if (productId_ != other.productId_) {
            return productId_ < other.productId_;
        }
        return serial_ < other.serial_;
    }

private:
    int32_t vendorId_ = -1;
    int32_t productId_ = -1;
    std::string serial_;
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_INCLUDE_ODD_BURN_USB_DEVICE_H
