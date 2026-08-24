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

#include "odd_burn_usb_device.h"
#include "edm_log.h"
#include "parcel_macro.h"

namespace OHOS {
namespace EDM {
bool OddBurnUsbDevice::Marshalling(MessageParcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, vendorId_);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, productId_);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, serial_);
    return true;
}

bool OddBurnUsbDevice::Unmarshalling(MessageParcel &parcel, OddBurnUsbDevice &device)
{
    int32_t vendorId = parcel.ReadInt32();
    int32_t productId = parcel.ReadInt32();
    std::string serial = parcel.ReadString();
    device.SetVendorId(vendorId);
    device.SetProductId(productId);
    device.SetSerial(serial);
    return true;
}

void OddBurnUsbDevice::SetVendorId(int32_t vendorId)
{
    vendorId_ = vendorId;
}

void OddBurnUsbDevice::SetProductId(int32_t productId)
{
    productId_ = productId;
}

void OddBurnUsbDevice::SetSerial(const std::string &serial)
{
    serial_ = serial;
}

int32_t OddBurnUsbDevice::GetVendorId() const
{
    return vendorId_;
}

int32_t OddBurnUsbDevice::GetProductId() const
{
    return productId_;
}

std::string OddBurnUsbDevice::GetSerial() const
{
    return serial_;
}
} // namespace EDM
} // namespace OHOS
