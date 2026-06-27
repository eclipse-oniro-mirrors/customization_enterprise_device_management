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

#include "array_string_serializer.h"

namespace OHOS {
namespace EDM {
bool ArrayStringSerializer::Deserialize(const std::string &jsonString, std::vector<std::string> &dataObj)
{
    dataObj.clear();
    if (jsonString.empty()) {
        return true;
    }
    cJSON *root = cJSON_Parse(jsonString.c_str());
    if (root == nullptr) {
        EDMLOGE("ArraySerializer Deserialize json to vector error");
        return false;
    }
    if (!cJSON_IsArray(root)) {
        EDMLOGE("Input JSON is not an array.");
        cJSON_Delete(root);
        return false;
    }
    cJSON *item = nullptr;
    cJSON_ArrayForEach(item, root) {
        if (cJSON_IsString(item)) {
            dataObj.push_back(item->valuestring);
        }
    }
    cJSON_Delete(root);
    return true;
}

bool ArrayStringSerializer::Serialize(const std::vector<std::string> &dataObj, std::string &jsonString)
{
    if (dataObj.empty()) {
        jsonString = "";
        return true;
    }

    cJSON *arrayData = nullptr;
    CJSON_CREATE_ARRAY_AND_CHECK(arrayData, false);
    for (const auto& item : dataObj) {
        cJSON *itemJsonObj = cJSON_CreateString(item.c_str());
        if (itemJsonObj == nullptr) {
            cJSON_Delete(arrayData);
            return false;
        }
        CJSON_ADD_ITEM_TO_ARRAY_AND_CHECK_AND_CLEAR(itemJsonObj, arrayData, false);
    }
    char *jsonStr = cJSON_PrintUnformatted(arrayData);
    if (jsonStr == nullptr) {
        cJSON_Delete(arrayData);
        return false;
    }
    jsonString = std::string(jsonStr);
    cJSON_Delete(arrayData);
    cJSON_free(jsonStr);
    return true;
}

bool ArrayStringSerializer::GetPolicy(MessageParcel &data, std::vector<std::string> &result)
{
    if (!data.ReadStringVector(&result)) {
        return false;
    }
    std::sort(result.begin(), result.end());
    auto iter = std::unique(result.begin(), result.end());
    result.erase(iter, result.end());
    return true;
}

bool ArrayStringSerializer::WritePolicy(MessageParcel &reply, std::vector<std::string> &result)
{
    return reply.WriteStringVector(result);
}

bool ArrayStringSerializer::MergePolicy(std::vector<std::vector<std::string>> &data, std::vector<std::string> &result)
{
    std::set<std::string> stData;
    for (const auto &dataItem : data) {
        for (const auto &item : dataItem) {
            stData.insert(item);
        }
    }
    result.assign(stData.begin(), stData.end());
    return true;
}

std::vector<std::string> ArrayStringSerializer::SetUnionPolicyData(std::vector<std::string> &data,
    std::vector<std::string> &currentData)
{
    std::vector<std::string> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_union(data.begin(), data.end(), currentData.begin(), currentData.end(), back_inserter(mergeData));
    return mergeData;
}

std::vector<std::string> ArrayStringSerializer::SetDifferencePolicyData(std::vector<std::string> &data,
    std::vector<std::string> &currentData)
{
    std::vector<std::string> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_difference(currentData.begin(), currentData.end(), data.begin(), data.end(), back_inserter(mergeData));
    return mergeData;
}

std::vector<std::string> ArrayStringSerializer::SetIntersectionPolicyData(std::vector<std::string> &data,
    std::vector<std::string> &currentData)
{
    std::vector<std::string> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_intersection(currentData.begin(), currentData.end(), data.begin(), data.end(), back_inserter(mergeData));
    return mergeData;
}
} // namespace EDM
} // namespace OHOS