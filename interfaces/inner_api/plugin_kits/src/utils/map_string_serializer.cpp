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

#include "map_string_serializer.h"
#include <string_ex.h>
#include "cjson_check.h"

namespace OHOS {
namespace EDM {
bool MapStringSerializer::Deserialize(const std::string &jsonString, std::map<std::string, std::string> &dataObj)
{
    if (jsonString.empty()) {
        return true;
    }

    cJSON *root = cJSON_Parse(jsonString.c_str());
    if (root == nullptr) {
        return false;
    }

    if (!cJSON_IsObject(root)) {
        EDMLOGE("JSON is not an object.");
        cJSON_Delete(root);
        return false;
    }

    cJSON *item = nullptr;
    cJSON_ArrayForEach(item, root) {
        if (!cJSON_IsString(item)) {
            EDMLOGE("item is not a string.");
            cJSON_Delete(root);
            return false;
        }
        dataObj.emplace(item->string, item->valuestring);
    }

    cJSON_Delete(root);
    return true;
}

bool MapStringSerializer::Serialize(const std::map<std::string, std::string> &dataObj, std::string &jsonString)
{
    cJSON *root = nullptr;
    CJSON_CREATE_OBJECT_AND_CHECK(root, false);

    for (const auto &item : dataObj) {
        if (!cJSON_AddStringToObject(root, item.first.c_str(), item.second.c_str())) {
            cJSON_Delete(root);
            return false;
        }
    }

    char *jsonStr = cJSON_Print(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return false;
    }

    jsonString = jsonStr;
    free(jsonStr);
    cJSON_Delete(root);
    return true;
}

bool MapStringSerializer::GetPolicy(MessageParcel &data, std::map<std::string, std::string> &result)
{
    std::vector<std::string> keys;
    std::vector<std::string> values;
    if (!data.ReadStringVector(&keys)) {
        EDMLOGE("MapStringSerializer::read map keys fail.");
        return false;
    }
    if (!data.ReadStringVector(&values)) {
        EDMLOGE("MapStringSerializer::read map values fail.");
        return false;
    }
    if (keys.size() != values.size()) {
        return false;
    }
    for (uint64_t i = 0; i < keys.size(); ++i) {
        result.insert(std::make_pair(keys.at(i), values.at(i)));
    }
    return true;
}

bool MapStringSerializer::WritePolicy(MessageParcel &reply, std::map<std::string, std::string> &result)
{
    std::vector<std::string> keys;
    std::vector<std::string> values;
    for (const auto &item : result) {
        keys.push_back(item.first);
        values.push_back(item.second);
    }
    return reply.WriteStringVector(keys) && reply.WriteStringVector(values);
}

bool MapStringSerializer::MergePolicy(std::vector<std::map<std::string, std::string>> &data,
    std::map<std::string, std::string> &result)
{
    if (!data.empty()) {
        result = *(data.rbegin());
    }
    return true;
}
} // namespace EDM
} // namespace OHOS