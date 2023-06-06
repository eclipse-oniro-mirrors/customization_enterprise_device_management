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

#ifndef SERVICES_EDM_INCLUDE_UTILS_WIFI_DEVICE_CONFIG_SERIALIZER_H
#define SERVICES_EDM_INCLUDE_UTILS_WIFI_DEVICE_CONFIG_SERIALIZER_H

#include "ipolicy_serializer.h"
#include "json/json.h"
#include "singleton.h"
#include "wifi_msg.h"

namespace OHOS {
namespace EDM {
/*
 * Policy data serializer of type int.
 */
class WifiDeviceConfigSerializer : public IPolicySerializer<Wifi::WifiDeviceConfig>,
    public DelayedSingleton<WifiDeviceConfigSerializer> {
public:
    bool Deserialize(const std::string &jsonString, Wifi::WifiDeviceConfig &dataObj) override;

    bool Serialize(const Wifi::WifiDeviceConfig &dataObj, std::string &jsonString) override;

    bool GetPolicy(MessageParcel &data, Wifi::WifiDeviceConfig &result) override;

    bool WritePolicy(MessageParcel &reply, Wifi::WifiDeviceConfig &result) override;

    bool MergePolicy(std::vector<Wifi::WifiDeviceConfig> &data, Wifi::WifiDeviceConfig &result) override;
private:
    Json::Value SerializerIpAddress(const Wifi::WifiIpAddress &address);
    Wifi::WifiIpAddress DeserializeIpAddress(const Json::Value &ipAddressJson);
    void ConvertStrToJson(const std::string &str, Json::Value &json);
    void ConvertJsonToStr(const Json::Value &json, std::string &str);
};
} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_UTILS_WIFI_DEVICE_CONFIG_SERIALIZER_H
