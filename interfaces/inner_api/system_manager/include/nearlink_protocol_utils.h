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

#ifndef INTERFACES_INNER_API_SYSTEM_MANAGER_INCLUDE_NEARLINK_PROTOCOL_UTILS_H
#define INTERFACES_INNER_API_SYSTEM_MANAGER_INCLUDE_NEARLINK_PROTOCOL_UTILS_H

#include <string>
#include <unordered_map>

namespace OHOS {
namespace EDM {
enum class NearlinkProtocol : uint32_t { SSAP = 0, DATA_TRANSFER = 1 };

class NearlinkProtocolUtils {
public:
    static bool IntToProtocolStr(int32_t value, std::string &str)
    {
        static const std::unordered_map<NearlinkProtocol, std::string> protocolToStrMap = {
            {NearlinkProtocol::SSAP, "SSAP"}, {NearlinkProtocol::DATA_TRANSFER, "DATA_TRANSFER"}};

        if (value < static_cast<int>(NearlinkProtocol::SSAP) ||
            value > static_cast<int>(NearlinkProtocol::DATA_TRANSFER)) {
            return false;
        }

        str = protocolToStrMap.at(static_cast<NearlinkProtocol>(value));
        return true;
    }

    static bool StrToProtocolInt(const std::string &str, int32_t &value)
    {
        static const std::unordered_map<std::string, NearlinkProtocol> strToProtocolMap = {
            {"SSAP", NearlinkProtocol::SSAP}, {"DATA_TRANSFER", NearlinkProtocol::DATA_TRANSFER}};

        auto it = strToProtocolMap.find(str);
        if (it == strToProtocolMap.end()) {
            return false;
        }

        value = static_cast<int32_t>(it->second);
        return true;
    }
};

}  // namespace EDM
}  // namespace OHOS

#endif  // INTERFACES_INNER_API_SYSTEM_MANAGER_INCLUDE_NEARLINK_PROTOCOL_UTILS_H