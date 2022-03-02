/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "long_serializer.h"
#include <string_ex.h>

namespace OHOS {
namespace EDM {
bool LongSerializer::Deserialize(const std::string &jsonString, int64_t &dataObj)
{
    dataObj = stoi(jsonString);
    return true;
}

bool LongSerializer::Serialize(const int64_t &dataObj, std::string &jsonString)
{
    jsonString = std::to_string(dataObj);
    return true;
}

bool LongSerializer::GetPolicy(MessageParcel &data, int64_t &result)
{
    result = data.ReadInt64();
    return true;
}

bool LongSerializer::WritePolicy(MessageParcel &reply, int64_t &result)
{
    return reply.WriteInt64(result);
}

bool LongSerializer::MergePolicy(std::vector<int64_t> &data, int64_t &result)
{
    for (auto iter = data.rbegin(); iter != data.rend(); ++iter) {
        result = *iter;
        return true;
    }
    return true;
}
} // namespace EDM
} // namespace OHOS