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

#include "edm_application_info.h"

#include <cstring>

#include "edm_log.h"
#include "string_ex.h"
#include "parcel_macro.h"

namespace OHOS {
namespace EDM {
bool EdmResource::ReadFromParcel(Parcel &parcel)
{
    bundleName = Str16ToStr8(parcel.ReadString16());
    moduleName = Str16ToStr8(parcel.ReadString16());
    id = parcel.ReadUint32();
    return true;
}

bool EdmResource::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(bundleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(moduleName));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, id);
    return true;
}

EdmResource *EdmResource::Unmarshalling(Parcel &parcel)
{
    EdmResource *resource = new (std::nothrow) EdmResource;
    if (resource && !resource->ReadFromParcel(parcel)) {
        EDMLOGE("read from parcel failed");
        delete resource;
        resource = nullptr;
    }
    return resource;
}

bool EdmApplicationInfo::ReadFromParcel(Parcel &parcel)
{
    removable = parcel.ReadBool();
    isSystemApp = parcel.ReadBool();
    debug = parcel.ReadBool();
    userDataClearable = parcel.ReadBool();
    enabled = parcel.ReadBool();

    accessTokenId = parcel.ReadUint32();
    iconId = parcel.ReadUint32();
    labelId = parcel.ReadUint32();
    descriptionId = parcel.ReadUint32();

    uid = parcel.ReadInt32();
    appIndex = parcel.ReadInt32();

    name = Str16ToStr8(parcel.ReadString16());
    description = Str16ToStr8(parcel.ReadString16());
    label = Str16ToStr8(parcel.ReadString16());
    icon = Str16ToStr8(parcel.ReadString16());
    process = Str16ToStr8(parcel.ReadString16());
    codePath = Str16ToStr8(parcel.ReadString16());
    appDistributionType = Str16ToStr8(parcel.ReadString16());
    appProvisionType = Str16ToStr8(parcel.ReadString16());
    nativeLibraryPath = Str16ToStr8(parcel.ReadString16());
    installSource = Str16ToStr8(parcel.ReadString16());
    apiReleaseType = Str16ToStr8(parcel.ReadString16());

    std::unique_ptr<EdmResource> iconResourcePtr(parcel.ReadParcelable<EdmResource>());
    if (!iconResourcePtr) {
        EDMLOGE("icon ReadParcelable<EdmResource> failed");
        return false;
    }
    iconResource = *iconResourcePtr;

    std::unique_ptr<EdmResource> labelResourcePtr(parcel.ReadParcelable<EdmResource>());
    if (!labelResourcePtr) {
        EDMLOGE("label ReadParcelable<EdmResource> failed");
        return false;
    }
    labelResource = *labelResourcePtr;

    std::unique_ptr<EdmResource> descriptionResourcePtr(parcel.ReadParcelable<EdmResource>());
    if (!descriptionResourcePtr) {
        EDMLOGE("description ReadParcelable<EdmResource> failed");
        return false;
    }
    descriptionResource = *descriptionResourcePtr;
    return true;
}

bool EdmApplicationInfo::Marshalling(Parcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, removable);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, isSystemApp);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, debug);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, userDataClearable);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Bool, parcel, enabled);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, accessTokenId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, iconId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, labelId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, descriptionId);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, uid);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(name));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(description));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(label));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(icon));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(process));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(codePath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appDistributionType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(appProvisionType));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(nativeLibraryPath));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(installSource));
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String16, parcel, Str8ToStr16(apiReleaseType));

    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &iconResource);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &labelResource);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Parcelable, parcel, &descriptionResource);
    return true;
}

EdmApplicationInfo *EdmApplicationInfo::Unmarshalling(Parcel &parcel)
{
    EdmApplicationInfo *info = new (std::nothrow) EdmApplicationInfo();
    if (info && !info->ReadFromParcel(parcel)) {
        EDMLOGE("read from parcel failed");
        delete info;
        info = nullptr;
    }
    return info;
}
} // namespace EDM
} // namespace OHOS