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

#include "uint_serializer.h"

#include <charconv>
#include <string_ex.h>
#include "edm_constants.h"

namespace OHOS {
namespace EDM {

bool UIntSerializer::Deserialize(const std::string &jsonString, uint32_t &dataObj)
{
    const char* begin = jsonString.data();
    const char* end = begin + jsonString.size();
    auto [ptr, ec] = std::from_chars(begin, end, dataObj);
    return (ec == std::errc() && ptr == end);
}

bool UIntSerializer::Serialize(const uint32_t &dataObj, std::string &jsonString)
{
    jsonString = std::to_string(dataObj);
    return true;
}

bool UIntSerializer::GetPolicy(MessageParcel &data, uint32_t &result)
{
    result = data.ReadUint32();
    return true;
}

bool UIntSerializer::WritePolicy(MessageParcel &reply, uint32_t &result)
{
    return reply.WriteUint32(result);
}

bool UIntSerializer::MergePolicy(std::vector<uint32_t> &data, uint32_t &result)
{
    for (auto policy : data) {
        if (policy != 0) {
            result = policy;
        }
    }
    return true;
}
} // namespace EDM
} // namespace OHOS