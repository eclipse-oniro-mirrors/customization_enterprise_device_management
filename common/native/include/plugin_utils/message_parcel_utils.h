/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef COMMON_NATIVE_INCLUDE_MESSAGE_PARCEL_UTILS_H
#define COMMON_NATIVE_INCLUDE_MESSAGE_PARCEL_UTILS_H

#include <string>

#include "edm_errors.h"
#include "message_parcel.h"
#include "wifi_msg.h"

namespace OHOS {
namespace EDM {
class MessageParcelUtils {
public:
    static void WriteWifiDeviceConfig(const Wifi::WifiDeviceConfig &config, MessageParcel &data);
    static void WriteIpAddress(MessageParcel &data, const Wifi::WifiIpAddress &address);
    static void ReadWifiDeviceConfig(MessageParcel &data, Wifi::WifiDeviceConfig &config);
    static void ProcessAssignIpMethod(int32_t ipMethod, Wifi::WifiIpConfig &ipConfig);
    static void ProcessPhase2Method(int32_t phase2, Wifi::WifiEapConfig &eapConfig);
    static void ProcessConfigureProxyMethod(int32_t proxyMethod, Wifi::WifiProxyConfig &proxyConfig);
    static void ProcessPrivacyConfig(int32_t privacyConfig, Wifi::WifiDeviceConfig &config);
    static void ReadIpAddress(MessageParcel &data, Wifi::WifiIpAddress &address);
};
} // namespace EDM
} // namespace OHOS
#endif // COMMON_NATIVE_INCLUDE_MESSAGE_PARCEL_UTILS_H