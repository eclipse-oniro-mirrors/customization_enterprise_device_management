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

#ifndef ENTERPRISE_DEVICE_MANAGEMENT_WIFI_ID_H
#define ENTERPRISE_DEVICE_MANAGEMENT_WIFI_ID_H

#include <string>
#include "message_parcel.h"

namespace OHOS {
namespace EDM {
class WifiId {
public:
    bool Marshalling(MessageParcel &parcel) const;
    static bool Unmarshalling(MessageParcel &parcel, WifiId &wifiId);

    void SetSsid(std::string ssid);
    void SetBssid(std::string bssid);

    std::string GetSsid() const;
    std::string GetBssid() const;

    bool operator<(const WifiId &other) const
    {
        return (GetSsid() == other.GetSsid()) ? (GetBssid() < other.GetBssid()) : (GetSsid() < other.GetSsid());
    }

private:
    std::string ssid_;
    std::string bssid_;
};
} // namespace EDM
} // namespace OHOS

#endif //ENTERPRISE_DEVICE_MANAGEMENT_WIFI_ID_H
