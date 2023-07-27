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

#include "wifi_device_config_serializer.h"
#include "message_parcel_utils.h"

namespace OHOS {
namespace EDM {
bool WifiDeviceConfigSerializer::Deserialize(const std::string &jsonString, Wifi::WifiDeviceConfig &config)
{
    return true;
}

bool WifiDeviceConfigSerializer::Serialize(const Wifi::WifiDeviceConfig &config, std::string &jsonString)
{
    return true;
}

bool WifiDeviceConfigSerializer::GetPolicy(MessageParcel &data, Wifi::WifiDeviceConfig &result)
{
    MessageParcelUtils::ReadWifiDeviceConfig(data, result);
    return true;
}

bool WifiDeviceConfigSerializer::WritePolicy(MessageParcel &reply, Wifi::WifiDeviceConfig &result)
{
    return true;
}

bool WifiDeviceConfigSerializer::MergePolicy(std::vector<Wifi::WifiDeviceConfig> &data, Wifi::WifiDeviceConfig &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS