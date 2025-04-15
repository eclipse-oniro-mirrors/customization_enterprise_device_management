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

#include "wifi_id.h"
#include "parcel_macro.h"
#include "edm_log.h"

namespace OHOS {
namespace EDM {
bool WifiId::Marshalling(MessageParcel &parcel) const
{
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, ssid_);
    WRITE_PARCEL_AND_RETURN_FALSE_IF_FAIL(String, parcel, bssid_);
    return true;
}

bool WifiId::Unmarshalling(MessageParcel &parcel, WifiId &wifiId)
{
    std::string ssid = parcel.ReadString();
    std::string bssid = parcel.ReadString();
    wifiId.SetSsid(ssid);
    wifiId.SetBssid(bssid);
    return true;
}

void WifiId::SetSsid(std::string ssid)
{
    ssid_ = ssid;
}

void WifiId::SetBssid(std::string bssid)
{
    bssid_ = bssid;
}

std::string WifiId::GetSsid() const
{
    return ssid_;
}

std::string WifiId::GetBssid() const
{
    return bssid_;
}
} // namespace EDM
} // namespace OHOS