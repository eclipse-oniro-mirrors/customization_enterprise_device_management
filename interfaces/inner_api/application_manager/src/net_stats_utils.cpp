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

#include "net_stats_utils.h"

#include "edm_log.h"
#include "parcel_macro.h"

namespace OHOS {
namespace EDM {
bool NetStatsNetwork::Marshalling(MessageParcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, bundleName);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, accountId);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, type);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, startTime);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, endTime);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, simId);
    return true;
}

bool NetStatsNetwork::ReadFromParcel(MessageParcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, bundleName);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, appIndex);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int32, parcel, accountId);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, type);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, startTime);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Int64, parcel, endTime);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint32, parcel, simId);
    return true;
}

bool NetStatsNetwork::Unmarshalling(MessageParcel &parcel, NetStatsNetwork &netStatsNetwork)
{
    return netStatsNetwork.ReadFromParcel(parcel);
}

bool NetStatsInfo::Marshalling(MessageParcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint64, parcel, rxBytes);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint64, parcel, txBytes);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint64, parcel, rxPackets);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint64, parcel, txPackets);
    return true;
}

bool NetStatsInfo::ReadFromParcel(MessageParcel &parcel)
{
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint64, parcel, rxBytes);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint64, parcel, txBytes);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint64, parcel, rxPackets);
    READ_PARCEL_AND_RETURN_FALSE_IF_FAIL(Uint64, parcel, txPackets);
    return true;
}

bool NetStatsInfo::Unmarshalling(MessageParcel &parcel, NetStatsInfo &netStatsInfo)
{
    return netStatsInfo.ReadFromParcel(parcel);
}
} // namespace EDM
} // namespace OHOS
