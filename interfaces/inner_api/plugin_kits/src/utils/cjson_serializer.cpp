/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "cjson_serializer.h"

namespace OHOS {
namespace EDM {
bool CjsonSerializer::Deserialize(const std::string &jsonString, cJSON* &dataObj)
{
    dataObj = cJSON_Parse(jsonString.c_str());
    return dataObj != nullptr;
}

bool CjsonSerializer::Serialize(cJSON *const &dataObj, std::string &jsonString)
{
    if (dataObj == nullptr) {
        return false;
    }
    char *cJsonStr = cJSON_Print(dataObj);
    if (cJsonStr != nullptr) {
        jsonString = std::string(cJsonStr);
        cJSON_free(cJsonStr);
    }
    return !jsonString.empty();
}

bool CjsonSerializer::GetPolicy(MessageParcel &data, cJSON* &result)
{
    std::string jsonString = data.ReadString();
    return Deserialize(jsonString, result);
}

bool CjsonSerializer::WritePolicy(MessageParcel &reply, cJSON* &result)
{
    std::string jsonString;
    if (!Serialize(result, jsonString)) {
        return false;
    }
    return reply.WriteString(jsonString);
}

bool CjsonSerializer::MergePolicy(std::vector<cJSON*> &data, cJSON* &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS