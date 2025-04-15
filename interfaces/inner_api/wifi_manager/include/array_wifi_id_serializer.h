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

#ifndef ENTERPRISE_DEVICE_MANAGEMENT_ARRAY_WIFI_ID_SERIALIZER_H
#define ENTERPRISE_DEVICE_MANAGEMENT_ARRAY_WIFI_ID_SERIALIZER_H

#include "edm_errors.h"
#include "ipolicy_serializer.h"
#include "singleton.h"
#include "wifi_id.h"

namespace OHOS {
namespace EDM {

class ArrayWifiIdSerializer : public IPolicySerializer<std::vector<WifiId>>,
    public DelayedSingleton<ArrayWifiIdSerializer> {
public:
    std::vector<WifiId> SetUnionPolicyData(std::vector<WifiId> &data, std::vector<WifiId> &currentData);
    std::vector<WifiId> SetDifferencePolicyData(std::vector<WifiId> &data,
        std::vector<WifiId> &currentData);
    bool Deserialize(const std::string &jsonString, std::vector<WifiId> &dataObj) override;
    bool Serialize(const std::vector<WifiId> &dataObj, std::string &jsonString) override;
    bool GetPolicy(MessageParcel &data, std::vector<WifiId> &result) override;
    bool WritePolicy(MessageParcel &reply, std::vector<WifiId> &result) override;
    bool MergePolicy(std::vector<std::vector<WifiId>> &data, std::vector<WifiId> &result) override;
    ErrCode QueryWifiListPolicy(const std::string &policyData, MessageParcel &reply);
};
} // namespace EDM
} // namespace OHOS

#endif //ENTERPRISE_DEVICE_MANAGEMENT_ARRAY_WIFI_ID_SERIALIZER_H
