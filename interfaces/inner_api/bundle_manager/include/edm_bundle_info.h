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

#ifndef INTERFACES_INNER_API_BUNDLE_MANAGER_INCLUDE_EDM_BUNDLE_INFO_H
#define INTERFACES_INNER_API_BUNDLE_MANAGER_INCLUDE_EDM_BUNDLE_INFO_H

#include <string>
#include <vector>

#include "edm_application_info.h"
#include "message_parcel.h"
#include "parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace EDM {
struct EdmSignatureInfo : public Parcelable {
    std::string appId;
    std::string fingerprint;
    std::string appIdentifier;
    std::string certificate;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static EdmSignatureInfo *Unmarshalling(Parcel &parcel);
};

struct EdmBundleInfo : public Parcelable {
    uint32_t versionCode = 0;
    uint32_t minCompatibleVersionCode = 0;
    uint32_t targetVersion = 0;

    int32_t appIndex = 0;

    int64_t installTime = 0;
    int64_t updateTime = 0;
    int64_t firstInstallTime = 0;

    std::string name;
    std::string vendor;
    std::string versionName;

    EdmSignatureInfo signatureInfo;
    EdmApplicationInfo applicationInfo;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static EdmBundleInfo *Unmarshalling(Parcel &parcel);
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_BUNDLE_MANAGER_INCLUDE_EDM_BUNDLE_INFO_H
