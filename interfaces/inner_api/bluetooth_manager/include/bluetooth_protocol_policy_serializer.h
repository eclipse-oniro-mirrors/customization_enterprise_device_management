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

#ifndef INTERFACES_INNER_API_BLUETOOTH_MANAGER_INCLUDE_BLUETOOTH_PROTOCOL_POLICY_SERIALIZER_H
#define INTERFACES_INNER_API_BLUETOOTH_MANAGER_INCLUDE_BLUETOOTH_PROTOCOL_POLICY_SERIALIZER_H

#include "bluetooth_protocol_models.h"
#include "edm_errors.h"
#include "ipolicy_serializer.h"
#include "singleton.h"

namespace OHOS {
namespace EDM {
class BluetoothProtocolPolicySerializer : public IPolicySerializer<BluetoothProtocolPolicy>,
    public DelayedSingleton<BluetoothProtocolPolicySerializer> {
public:
    bool Deserialize(const std::string &jsonString, BluetoothProtocolPolicy &dataObj) override;

    bool Serialize(const BluetoothProtocolPolicy &dataObj, std::string &jsonString) override;

    bool GetPolicy(MessageParcel &data, BluetoothProtocolPolicy &result) override;

    bool WritePolicy(MessageParcel &reply, BluetoothProtocolPolicy &result) override;

    bool MergePolicy(std::vector<BluetoothProtocolPolicy> &data, BluetoothProtocolPolicy &result) override;

    bool IntToProtocolStr(int32_t value, std::string &str);

    bool StrToProtocolInt(const std::string &str, int32_t &value);
private:
    static const std::unordered_map<BtProtocol, std::string> protocolToStrMap;
    static const std::unordered_map<std::string, BtProtocol> strToProtocolMap;
};
}
}
#endif // INTERFACES_INNER_API_BLUETOOTH_MANAGER_INCLUDE_BLUETOOTH_PROTOCOL_POLICY_SERIALIZER_H
