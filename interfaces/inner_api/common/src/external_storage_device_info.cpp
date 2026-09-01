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

#include "external_storage_device_info.h"

namespace OHOS {
namespace EDM {
bool ExternalStorageDeviceInfo::Marshalling(Parcel &parcel) const
{
    return parcel.WriteInt32(type) && parcel.WriteString(devicePath) && parcel.WriteString(volumeId) &&
           parcel.WriteBool(mountStatus) && parcel.WriteInt32(vendorId) && parcel.WriteInt32(productId) &&
           parcel.WriteString(serial);
}

ExternalStorageDeviceInfo *ExternalStorageDeviceInfo::Unmarshalling(Parcel &parcel)
{
    ExternalStorageDeviceInfo *info = new (std::nothrow) ExternalStorageDeviceInfo();
    if (info == nullptr) {
        return nullptr;
    }
    bool ret = parcel.ReadInt32(info->type) && parcel.ReadString(info->devicePath) &&
        parcel.ReadString(info->volumeId) && parcel.ReadBool(info->mountStatus) &&
        parcel.ReadInt32(info->vendorId) && parcel.ReadInt32(info->productId) && parcel.ReadString(info->serial);
    if (!ret) {
        delete info;
        return nullptr;
    }
    return info;
}
} // namespace EDM
} // namespace OHOS
