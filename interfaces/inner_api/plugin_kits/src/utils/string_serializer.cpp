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

#include "string_serializer.h"
#include <string_ex.h>

namespace OHOS {
namespace EDM {
bool StringSerializer::Deserialize(const std::string &jsonString, std::string &dataObj)
{
    dataObj = jsonString;
    return true;
}

bool StringSerializer::Serialize(const std::string &dataObj, std::string &jsonString)
{
    jsonString = dataObj;
    return true;
}

bool StringSerializer::GetPolicy(MessageParcel &data, std::string &result)
{
    result = Str16ToStr8(data.ReadString16());
    return true;
}

bool StringSerializer::WritePolicy(MessageParcel &reply, std::string &result)
{
    return reply.WriteString16(Str8ToStr16(result));
}

bool StringSerializer::MergePolicy(std::vector<std::string> &data, std::string &result)
{
    for (auto iter = data.rbegin(); iter != data.rend(); ++iter) {
        result = *iter;
        return true;
    }
    return true;
}
} // namespace EDM
} // namespace OHOS