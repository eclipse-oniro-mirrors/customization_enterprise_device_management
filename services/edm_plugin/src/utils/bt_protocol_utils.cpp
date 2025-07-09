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

#include "bt_protocol_utils.h"

namespace OHOS {
namespace EDM {
const std::unordered_map<BtProtocol, std::string> BtProtocolUtils::protocolToStrMap = {
    {BtProtocol::GATT, "GATT"},
    {BtProtocol::SPP, "SPP"},
    {BtProtocol::OPP, "OPP"}
};

const std::unordered_map<std::string, BtProtocol> BtProtocolUtils::strToProtocolMap = {
    {"GATT", BtProtocol::GATT},
    {"SPP", BtProtocol::SPP},
    {"OPP", BtProtocol::OPP}
};

bool BtProtocolUtils::IntToProtocolStr(int32_t value, std::string &str)
{
    if (value < static_cast<int>(BtProtocol::GATT) || value > static_cast<int>(BtProtocol::OPP)) {
        return false;
    }
    auto it = protocolToStrMap.find(static_cast<BtProtocol>(value));
    if (it != protocolToStrMap.end()) {
        str = it->second;
        return true;
    }
    return false;
}

bool BtProtocolUtils::StrToProtocolInt(const std::string &str, int32_t &value)
{
    auto it = strToProtocolMap.find(str);
    if (it == strToProtocolMap.end()) {
        return false;
    }
    value = static_cast<int32_t>(it->second);
    return true;
}
}  // namespace EDM
}  // namespace OHOS