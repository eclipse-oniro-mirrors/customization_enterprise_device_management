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

#include "array_int_serializer.h"

namespace OHOS {
namespace EDM {
bool ArrayIntSerializer::Deserialize(const std::string &jsonString, std::vector<int32_t> &dataObj)
{
    return true;
}

bool ArrayIntSerializer::Serialize(const std::vector<int32_t> &dataObj, std::string &jsonString)
{
    return true;
}

bool ArrayIntSerializer::GetPolicy(MessageParcel &data, std::vector<int32_t> &result)
{
    std::vector<int32_t> readVector;
    if (!data.ReadInt32Vector(&readVector)) {
        return false;
    }
    // Data will be appended to result, and the original data of result will not be deleted.
    for (const auto &item : readVector) {
        result.push_back(item);
    }
    Deduplication(result);
    return true;
}

bool ArrayIntSerializer::WritePolicy(MessageParcel &reply, std::vector<int32_t> &result)
{
    return true;
}

bool ArrayIntSerializer::MergePolicy(std::vector<std::vector<int32_t>> &data, std::vector<int32_t> &result)
{
    return true;
}

void ArrayIntSerializer::Deduplication(std::vector<int32_t> &dataObj)
{
    std::sort(dataObj.begin(), dataObj.end());
    auto iter = std::unique(dataObj.begin(), dataObj.end());
    dataObj.erase(iter, dataObj.end());
}
} // namespace EDM
} // namespace OHOS