/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNER_API_INCLUDE_ENT_INFO_H
#define INTERFACES_INNER_API_INCLUDE_ENT_INFO_H

#include <string>
#include "message_parcel.h"

namespace OHOS {
namespace EDM {
struct EntInfo {
    EntInfo(const std::string &enterpriseName, const std::string &description);
    EntInfo();
    ~EntInfo();

    std::string enterpriseName;
    std::string description;
    bool ReadFromParcel(MessageParcel &parcel);
    bool Marshalling(MessageParcel &parcel) const;
    static bool Unmarshalling(MessageParcel &parcel, EntInfo &entInfo);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_INCLUDE_ENT_INFO_H
