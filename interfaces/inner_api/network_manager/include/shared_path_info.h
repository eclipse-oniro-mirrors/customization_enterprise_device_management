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

#ifndef INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_SHARED_PATH_INFO_H
#define INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_SHARED_PATH_INFO_H

#include <cstdint>
#include <string>

#include "message_parcel.h"

namespace OHOS {
namespace EDM {

constexpr uint32_t SHARED_PATH_MAX_COUNT = 10000;

struct PathSharedData {
    std::string shareName;
    std::string shareUri;

    bool Marshalling(MessageParcel &parcel) const
    {
        parcel.WriteString(shareName);
        parcel.WriteString(shareUri);
        return true;
    }

    static PathSharedData Unmarshalling(MessageParcel &parcel)
    {
        PathSharedData data;
        data.shareName = parcel.ReadString();
        data.shareUri = parcel.ReadString();
        return data;
    }
};

} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_SHARED_PATH_INFO_H
