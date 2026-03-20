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

#ifndef INTERFACES_INNER_API_APPLICATION_MANAGER_INCLUDE_NET_STATS_UTILS_H
#define INTERFACES_INNER_API_APPLICATION_MANAGER_INCLUDE_NET_STATS_UTILS_H

#include <string>

#include "message_parcel.h"

namespace OHOS {
namespace EDM {
struct NetStatsNetwork {
    std::string bundleName;
    int32_t appIndex = 0;
    int32_t accountId = 0;
    uint32_t type = 0;
    int64_t startTime = 0;
    int64_t endTime = 0;
    uint32_t simId = UINT32_MAX;

    bool Marshalling(MessageParcel &parcel) const;
    bool ReadFromParcel(MessageParcel &parcel);
    static bool Unmarshalling(MessageParcel &parcel, NetStatsNetwork &netStatsNetwork);
};

struct NetStatsInfo {
    uint64_t rxBytes = 0;
    uint64_t txBytes = 0;
    uint64_t rxPackets = 0;
    uint64_t txPackets = 0;

    bool Marshalling(MessageParcel &parcel) const;
    bool ReadFromParcel(MessageParcel &parcel);
    static bool Unmarshalling(MessageParcel &parcel, NetStatsInfo &netStatsInfo);
};
} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_INNER_API_APPLICATION_MANAGER_INCLUDE_NET_STATS_UTILS_H
