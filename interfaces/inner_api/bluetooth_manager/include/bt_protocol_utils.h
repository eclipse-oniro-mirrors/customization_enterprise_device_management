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

#ifndef INTERFACES_KITS_BLUETOOTH_MANAGER_INCLUDE_BT_PROTOCOL_UTILS_H
#define INTERFACES_KITS_BLUETOOTH_MANAGER_INCLUDE_BT_PROTOCOL_UTILS_H

#include <string>
#include <unordered_map>

namespace OHOS {
namespace EDM {
enum class BtProtocol : uint32_t {
    GATT = 0,
    SPP = 1
};

class BtProtocolUtils {
public:
    bool IntToProtocolStr(const int32_t &value, std::string &str)
    {
        if (value < static_cast<int>(BtProtocol::GATT) || value > static_cast<int>(BtProtocol::SPP)) {
            return false;
        }
        std::unordered_map<BtProtocol, std::string> protocolToStrMap {
            {BtProtocol::GATT, "GATT"},
            {BtProtocol::SPP, "SPP"}
        };
        str = protocolToStrMap.at(static_cast<BtProtocol>(value));
        return true;
    }

    bool StrToProtocolInt(const std::string &str, int32_t &value)
    {
        std::unordered_map<std::string, BtProtocol> StrToProtocolMap {
            {"GATT", BtProtocol::GATT},
            {"SPP", BtProtocol::SPP}
        };
        auto it = StrToProtocolMap.find(str);
        if (it == StrToProtocolMap.end()) {
            return false;
        }
        value = static_cast<int>(it->second);
        return true;
    }
};

} // namespace EDM
} // namespace OHOS

#endif // INTERFACES_KITS_BLUETOOTH_MANAGER_INCLUDE_BT_PROTOCOL_UTILS_H

