/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "usb_device_id.h"
#include "edm_log.h"
#include "parcel_macro.h"

namespace OHOS {
namespace EDM {
bool UsbDeviceId::Marshalling(MessageParcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, vendorId_);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, productId_);
    return true;
}

bool UsbDeviceId::Unmarshalling(MessageParcel &parcel, UsbDeviceId &usbDeviceId)
{
    int32_t vendorId = parcel.ReadInt32();
    int32_t productId = parcel.ReadInt32();
    usbDeviceId.SetVendorId(vendorId);
    usbDeviceId.SetProductId(productId);
    return true;
}

void UsbDeviceId::SetVendorId(int32_t vendorId)
{
    vendorId_ = vendorId;
}

void UsbDeviceId::SetProductId(int32_t productId)
{
    productId_ = productId;
}

int32_t UsbDeviceId::GetVendorId() const
{
    return vendorId_;
}

int32_t UsbDeviceId::GetProductId() const
{
    return productId_;
}
} // namespace EDM
} // namespace OHOS
