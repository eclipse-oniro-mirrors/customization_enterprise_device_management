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
#include "cJSON.h"
#include "cjson_check.h"
#include "edm_constants.h"

namespace OHOS {
namespace EDM {

std::vector<int32_t> ArrayIntSerializer::SetUnionPolicyData(std::vector<int32_t> &data,
    std::vector<int32_t> &currentData)
{
    std::vector<int32_t> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_union(data.begin(), data.end(), currentData.begin(), currentData.end(), back_inserter(mergeData));
    return mergeData;
}

std::vector<int32_t> ArrayIntSerializer::SetDifferencePolicyData(std::vector<int32_t> &data,
    std::vector<int32_t> &currentData)
{
    std::vector<int32_t> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_difference(currentData.begin(), currentData.end(), data.begin(), data.end(), back_inserter(mergeData));
    return mergeData;
}

bool ArrayIntSerializer::Deserialize(const std::string &jsonString, std::vector<int32_t> &dataObj)
{
    cJSON* json = cJSON_Parse(jsonString.c_str());
    if (json == nullptr) {
        return true;
    }
    if (!cJSON_IsArray(json)) {
        cJSON_Delete(json);
        return false;
    }
    cJSON *item = json->child;
    while (item != nullptr) {
        if (cJSON_IsNumber(item)) {
            int32_t value = (int32_t)item->valueint;
            dataObj.push_back(value);
        }
        item = item->next;
    }
    cJSON_Delete(json);
    return true;
}

bool ArrayIntSerializer::Serialize(const std::vector<int32_t> &dataObj, std::string &jsonString)
{
    if (dataObj.empty()) {
        return true;
    }
    cJSON* jsonArray = nullptr;
    CJSON_CREATE_ARRAY_AND_CHECK(jsonArray, false);
    for (const auto& item : dataObj) {
        cJSON_AddItemToArray(jsonArray, cJSON_CreateNumber(item));
    }
    char* jsonStr = cJSON_Print(jsonArray);
    if (jsonStr == nullptr) {
        cJSON_Delete(jsonArray);
        return false;
    }
    jsonString = std::string(jsonStr);
    cJSON_free(jsonStr);
    cJSON_Delete(jsonArray);
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
    std::set<int32_t> stData;
    for (const auto &dataItem : data) {
        for (const auto &item : dataItem) {
            stData.insert(item);
        }
    }
    result.assign(stData.begin(), stData.end());
    Deduplication(result);
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