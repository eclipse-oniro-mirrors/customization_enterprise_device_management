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

#ifndef INTERFACES_INNER_API_BUNDLE_MANAGER_INCLUDE_BUNDLE_STORAGE_INFO_H
#define INTERFACES_INNER_API_BUNDLE_MANAGER_INCLUDE_BUNDLE_STORAGE_INFO_H

#include <string>
#include <vector>

#include "message_parcel.h"
#include "parcel.h"
#include "string_ex.h"

namespace OHOS {
namespace EDM {

struct BundleStorageInfo : public Parcelable {
    std::string bundleName;
    int64_t appSize = 0;
    int64_t dataSize = 0;

    bool ReadFromParcel(Parcel &parcel);
    virtual bool Marshalling(Parcel &parcel) const override;
    static BundleStorageInfo *Unmarshalling(Parcel &parcel);
};
} // namespace EDM
} // namespace OHOS
#endif // INTERFACES_INNER_API_BUNDLE_MANAGER_INCLUDE_BUNDLE_STORAGE_INFO_H
