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

#ifndef SERVICES_EDM_INCLUDE_UTILS_BT_PROTOCOL_UTILS_H
#define SERVICES_EDM_INCLUDE_UTILS_BT_PROTOCOL_UTILS_H

#include <string>
#include <unordered_map>

namespace OHOS {
namespace EDM {
enum class BtProtocol : uint32_t {
    GATT = 0,
    SPP = 1,
    OPP = 2,
};

class BtProtocolUtils {
public:
    static const std::unordered_map<BtProtocol, std::string> protocolToStrMap;
    static const std::unordered_map<std::string, BtProtocol> strToProtocolMap;
    static bool IntToProtocolStr(int32_t value, std::string &str);
    static bool StrToProtocolInt(const std::string &str, int32_t &value);
};

} // namespace EDM
} // namespace OHOS

#endif // SERVICES_EDM_INCLUDE_UTILS_BT_PROTOCOL_UTILS_H

