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

#ifndef INTERFACES_INNER_API_COMMON_INCLUDE_PATCH_INFO_H
#define INTERFACES_INNER_API_COMMON_INCLUDE_PATCH_INFO_H

#include <cstdint>
#include <string>
#include <vector>

#include "message_parcel.h"

namespace OHOS {
namespace EDM {

struct PatchDescriptionBody {
    std::string title;
    std::vector<std::string> contents;

    bool Marshalling(Parcel &parcel) const;
    static bool Unmarshalling(Parcel &parcel, PatchDescriptionBody &body);
};

struct PatchDescription {
    std::vector<std::string> headers;
    std::vector<PatchDescriptionBody> bodies;

    bool Marshalling(Parcel &parcel) const;
    static bool Unmarshalling(Parcel &parcel, PatchDescription &description);
};

class PatchInfo : public Parcelable {
public:
    PatchInfo() = default;
    ~PatchInfo() = default;

    bool Marshalling(Parcel &parcel) const override;
    static bool Unmarshalling(Parcel &parcel, PatchInfo &info);

    std::string name;
    std::string accountName;
    int64_t installTime = 0;
    PatchDescription description;
};

} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_COMMON_INCLUDE_PATCH_INFO_H
