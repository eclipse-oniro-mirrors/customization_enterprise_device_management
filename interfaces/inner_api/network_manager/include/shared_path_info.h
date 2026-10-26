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
#include <vector>

#include "message_parcel.h"

namespace OHOS {
namespace EDM {

constexpr uint32_t SHARED_PATH_MAX_COUNT = 10000;

struct UserPathInfo {
    std::string userName;
    std::string userPermission;

    bool Marshalling(MessageParcel &parcel) const
    {
        parcel.WriteString(userName);
        parcel.WriteString(userPermission);
        return true;
    }

    static UserPathInfo Unmarshalling(MessageParcel &parcel)
    {
        UserPathInfo info;
        info.userName = parcel.ReadString();
        info.userPermission = parcel.ReadString();
        return info;
    }
};

struct PathSharedData {
    std::string shareName;
    std::string shareUri;
    std::vector<UserPathInfo> userPathInfoList;
    int32_t shareLimit = 0;

    bool Marshalling(MessageParcel &parcel) const
    {
        parcel.WriteString(shareName);
        parcel.WriteString(shareUri);
        parcel.WriteUint32(userPathInfoList.size());
        for (const auto &u : userPathInfoList) {
            u.Marshalling(parcel);
        }
        parcel.WriteInt32(shareLimit);
        return true;
    }

    static PathSharedData Unmarshalling(MessageParcel &parcel)
    {
        PathSharedData data;
        data.shareName = parcel.ReadString();
        data.shareUri = parcel.ReadString();
        uint32_t size = parcel.ReadUint32();
        if (size > SHARED_PATH_MAX_COUNT) {
            for (uint32_t i = 0; i < size; ++i) {
                UserPathInfo::Unmarshalling(parcel);
            }
            parcel.ReadInt32();
            data.shareLimit = 0;
            return data;
        }
        data.userPathInfoList.reserve(size);
        for (uint32_t i = 0; i < size; ++i) {
            data.userPathInfoList.push_back(UserPathInfo::Unmarshalling(parcel));
        }
        data.shareLimit = parcel.ReadInt32();
        return data;
    }
};

} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_NETWORK_MANAGER_INCLUDE_SHARED_PATH_INFO_H
