/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "int_serializer.h"

#include <string_ex.h>
#include "edm_constants.h"

namespace OHOS {
namespace EDM {

bool IntSerializer::Deserialize(const std::string &jsonString, int32_t &dataObj)
{
    dataObj = strtol(jsonString.c_str(), nullptr, EdmConstants::DECIMAL);
    return true;
}

bool IntSerializer::Serialize(const int32_t &dataObj, std::string &jsonString)
{
    jsonString = std::to_string(dataObj);
    return true;
}

bool IntSerializer::GetPolicy(MessageParcel &data, int32_t &result)
{
    result = data.ReadInt32();
    return true;
}

bool IntSerializer::WritePolicy(MessageParcel &reply, int32_t &result)
{
    return reply.WriteInt32(result);
}

bool IntSerializer::MergePolicy(std::vector<int32_t> &data, int32_t &result)
{
    if (!data.empty()) {
        result = *(data.rbegin());
    }
    return true;
}
} // namespace EDM
} // namespace OHOS