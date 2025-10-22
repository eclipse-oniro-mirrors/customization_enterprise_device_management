/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_BUNDLE_MANAGER_INCLUDE_EDM_APPLICATION_INFO_H
#define INTERFACES_INNER_API_BUNDLE_MANAGER_INCLUDE_EDM_APPLICATION_INFO_H

#include <string>

#include "edm_constants.h"
#include "parcel.h"

namespace OHOS {
namespace EDM {
struct EdmResource : public Parcelable {
    /** the resource id in hap */
    uint32_t id = 0;

    /** the hap bundle name */
    std::string bundleName;

    /** the hap module name */
    std::string moduleName;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static EdmResource *Unmarshalling(Parcel &parcel);
};

struct EdmApplicationInfo : public Parcelable {
    bool removable = true;
    bool isSystemApp = false;
    bool debug = false;
    bool userDataClearable = true;
    bool enabled = false;

    uint32_t accessTokenId = 0;
    uint32_t iconId = 0;
    uint32_t labelId = 0;
    uint32_t descriptionId = 0;

    int32_t uid = -1;
    int32_t appIndex = 0;

    std::string name;
    std::string description;
    std::string label;
    std::string icon;
    std::string iconData;
    std::string process;
    std::string codePath;
    std::string appDistributionType = EdmConstants::APP_DISTRIBUTION_TYPE_NONE;
    std::string appProvisionType = EdmConstants::APP_PROVISION_TYPE_RELEASE;
    std::string nativeLibraryPath;
    std::string installSource;
    std::string apiReleaseType;

    EdmResource iconResource;
    EdmResource labelResource;
    EdmResource descriptionResource;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static EdmApplicationInfo *Unmarshalling(Parcel &parcel);
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_BUNDLE_MANAGER_INCLUDE_EDM_APPLICATION_INFO_H
