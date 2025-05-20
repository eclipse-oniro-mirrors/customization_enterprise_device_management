/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "edm_bundle_info.h"

#include <cstring>

#include "edm_log.h"
#include "parcel.h"
#include "parcel_macro.h"
#include "string_ex.h"

namespace OHOS {
namespace EDM {
bool EdmSignatureInfo::ReadFromParcel(Parcel &parcel)
{
    appId = Str16ToStr8(parcel.ReadString16());
    fingerprint = Str16ToStr8(parcel.ReadString16());
    appIdentifier = Str16ToStr8(parcel.ReadString16());
    certificate = Str16ToStr8(parcel.ReadString16());
    return true;
}

bool EdmSignatureInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appId));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(fingerprint));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appIdentifier));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(certificate));
    return true;
}

EdmSignatureInfo *EdmSignatureInfo::Unmarshalling(Parcel &parcel)
{
    EdmSignatureInfo *info = new (std::nothrow) EdmSignatureInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        EDMLOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

bool EdmBundleInfo::ReadFromParcel(Parcel &parcel)
{
    versionCode = parcel.ReadUint32();
    minCompatibleVersionCode = parcel.ReadUint32();
    targetVersion = parcel.ReadUint32();
    appIndex = parcel.ReadInt32();
    installTime = parcel.ReadInt64();
    updateTime = parcel.ReadInt64();
    firstInstallTime = parcel.ReadInt64();

    name = Str16ToStr8(parcel.ReadString16());
    vendor = Str16ToStr8(parcel.ReadString16());
    versionName = Str16ToStr8(parcel.ReadString16());

    std::unique_ptr<EdmSignatureInfo> sigInfo(parcel.ReadParcelable<EdmSignatureInfo>());
    if (!sigInfo) {
        EDMLOGE("ReadParcelable<SignatureInfo> failed");
        return false;
    }
    signatureInfo = *sigInfo;

    std::unique_ptr<EdmApplicationInfo> appInfo(parcel.ReadParcelable<EdmApplicationInfo>());
    if (!appInfo) {
        EDMLOGE("ReadParcelable<EdmApplicationInfo> failed");
        return false;
    }
    applicationInfo = *appInfo;
    return true;
}

bool EdmBundleInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, versionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, minCompatibleVersionCode);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, targetVersion);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, installTime);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, updateTime);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, firstInstallTime);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(vendor));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(versionName));

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &signatureInfo);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &applicationInfo);
    return true;
}

EdmBundleInfo *EdmBundleInfo::Unmarshalling(Parcel &parcel)
{
    EdmBundleInfo *info = new (std::nothrow) EdmBundleInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        EDMLOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}

} // namespace EDM
} // namespace OHOS