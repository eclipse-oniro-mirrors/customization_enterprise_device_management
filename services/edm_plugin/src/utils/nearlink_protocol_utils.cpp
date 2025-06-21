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

#include "nearlink_protocol_utils.h"

namespace OHOS {
namespace EDM {
const std::unordered_map<NearlinkProtocol, std::string> NearlinkProtocolUtils::protocolToStrMap = {
    {NearlinkProtocol::SSAP, "SSAP"},
    {NearlinkProtocol::DATA_TRANSFER, "DATA_TRANSFER"}
};

const std::unordered_map<std::string, NearlinkProtocol> NearlinkProtocolUtils::strToProtocolMap = {
    {"SSAP", NearlinkProtocol::SSAP},
    {"DATA_TRANSFER", NearlinkProtocol::DATA_TRANSFER}
};

bool NearlinkProtocolUtils::IntToProtocolStr(int32_t value, std::string &str)
{
    if (value < static_cast<int>(NearlinkProtocol::SSAP) || value > static_cast<int>(NearlinkProtocol::DATA_TRANSFER)) {
        return false;
    }

     // 安全转换为枚举类型并获取对应的字符串
    auto it = protocolToStrMap.find(static_cast<NearlinkProtocol>(value));
    if (it != protocolToStrMap.end()) {
        str = it->second;
        return true;
    }

    return false;
}

bool NearlinkProtocolUtils::StrToProtocolInt(const std::string &str, int32_t &value)
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