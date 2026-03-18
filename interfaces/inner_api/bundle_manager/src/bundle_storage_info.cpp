/*
 * Copyright (c) 2026-2026 Huawei Device Co., Ltd.
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

#include "bundle_storage_info.h"

#include <cstring>

#include "edm_log.h"
#include "parcel.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace EDM {
bool BundleStorageInfo::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    appSize = parcel.ReadInt64();
    dataSize = parcel.ReadInt64();
    return true;
}

bool BundleStorageInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, appSize);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, dataSize);
    return true;
}

BundleStorageInfo *BundleStorageInfo::Unmarshalling(Parcel &parcel)
{
    BundleStorageInfo *info = new (std::nothrow) BundleStorageInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        EDMLOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // namespace EDM
} // namespace OHOS