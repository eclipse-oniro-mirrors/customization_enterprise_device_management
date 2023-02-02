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

#include "bool_serializer.h"

namespace OHOS {
namespace EDM {
bool BoolSerializer::Deserialize(const std::string &jsonString, bool &dataObj)
{
    constexpr std::size_t TRUE_STRING_SIZE = 4;
    constexpr std::size_t FALSE_STRING_SIZE = 5;
    if (jsonString.size() != TRUE_STRING_SIZE && jsonString.size() != FALSE_STRING_SIZE) {
        return false;
    }
    std::string temp;
    temp.resize(jsonString.size());
    std::transform(jsonString.begin(), jsonString.end(), temp.begin(), ::tolower);
    if (temp == TRUE_VALUE) {
        dataObj = true;
        return true;
    }
    if (temp == FALSE_VALUE) {
        dataObj = false;
        return true;
    }
    return false;
}

bool BoolSerializer::Serialize(const bool &dataObj, std::string &jsonString)
{
    jsonString = dataObj ? TRUE_VALUE : "";
    return true;
}

bool BoolSerializer::GetPolicy(MessageParcel &data, bool &result)
{
    return data.ReadBool(result);
}

bool BoolSerializer::WritePolicy(MessageParcel &reply, bool &result)
{
    return reply.WriteBool(result);
}

bool BoolSerializer::MergePolicy(std::vector<bool> &data, bool &result)
{
    for (bool item : data) {
        if (item) {
            result = true;
            return true;
        }
    }
    result = false;
    return true;
}
} // namespace EDM
} // namespace OHOS