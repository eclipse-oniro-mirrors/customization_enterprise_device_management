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

#ifndef INTERFACES_INNER_API_COMMON_INCLUDE_EXTERNAL_STORAGE_DEVICE_INFO_H
#define INTERFACES_INNER_API_COMMON_INCLUDE_EXTERNAL_STORAGE_DEVICE_INFO_H

#include <string>
#include <cstdint>

#include "message_parcel.h"

namespace OHOS {
namespace EDM {

enum class DiskType : int32_t {
    SD_CARD = 1,
    USB_FLASH = 2,
    CD_DVD_BD = 3,
};

class ExternalStorageDeviceInfo : public Parcelable {
public:
    ExternalStorageDeviceInfo() = default;
    ~ExternalStorageDeviceInfo() = default;

    bool Marshalling(Parcel &parcel) const override;
    static ExternalStorageDeviceInfo *Unmarshalling(Parcel &parcel);

    int32_t type = 0;
    std::string devicePath;
    std::string volumeId;
    bool mountStatus = false;
    int32_t vendorId = -1;
    int32_t productId = -1;
    std::string serial;
};

} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_COMMON_INCLUDE_EXTERNAL_STORAGE_DEVICE_INFO_H
