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

#include "telephony_call_policy_serializer.h"

#include <unordered_set>
#include "cJSON.h"
#include "cjson_check.h"

namespace OHOS {
namespace EDM {

const char* const POLICY_FLAG = "policyFlag";
const char* const NUMBER_LIST = "numberList";

bool TelephonyCallPolicySerializer::Deserialize(const std::string &policy,
    std::map<std::string, TelephonyCallPolicyType> &dataObj)
{
    if (policy.empty()) {
        return true;
    }
    cJSON* root = cJSON_Parse(policy.c_str());
    if (root == nullptr) {
        return false;
    }
    cJSON* mapItem;
    cJSON_ArrayForEach(mapItem, root) {
        cJSON* policyFlag = cJSON_GetObjectItem(mapItem, POLICY_FLAG);
        cJSON* numberList = cJSON_GetObjectItem(mapItem, NUMBER_LIST);
        if (!cJSON_IsArray(numberList) || !cJSON_IsNumber(policyFlag)) {
            cJSON_Delete(root);
            return false;
        }
        std::vector<std::string> numberVector;
        cJSON* vectorItem;
        cJSON_ArrayForEach(vectorItem, numberList) {
            char* policyValue = cJSON_GetStringValue(vectorItem);
            if (policyValue == nullptr) {
                cJSON_Delete(root);
                return false;
            }
            numberVector.push_back(std::string(policyValue));
        }
        dataObj[mapItem->string].numberList = numberVector;
        dataObj[mapItem->string].policyFlag = policyFlag->valueint;
    }
    cJSON_Delete(root);
    return true;
}

bool TelephonyCallPolicySerializer::Serialize(const std::map<std::string, TelephonyCallPolicyType> &dataObj,
    std::string &policy)
{
    cJSON* root = nullptr;
    CJSON_CREATE_OBJECT_AND_CHECK(root, false);
    for (auto& mapIt : dataObj) {
        cJSON* policyObject = nullptr;
        CJSON_CREATE_OBJECT_AND_CHECK_AND_CLEAR(policyObject, false, root);
        cJSON_AddNumberToObject(policyObject, POLICY_FLAG, mapIt.second.policyFlag);
        cJSON* array = cJSON_CreateArray();
        if (array == nullptr) {
            cJSON_Delete(root);
            cJSON_Delete(policyObject);
            return false;
        }
        for (auto& vectorIt : mapIt.second.numberList) {
            cJSON* policyValue = cJSON_CreateString(vectorIt.c_str());
            if (policyValue == nullptr) {
                cJSON_Delete(root);
                cJSON_Delete(policyObject);
                cJSON_Delete(array);
                return false;
            }
            cJSON_AddItemToArray(array, policyValue);
        }
        if (!cJSON_AddItemToObject(policyObject, NUMBER_LIST, array)) {
            cJSON_Delete(root);
            cJSON_Delete(policyObject);
            cJSON_Delete(array);
            return false;
        }
        if (!cJSON_AddItemToObject(root, mapIt.first.c_str(), policyObject)) {
            cJSON_Delete(root);
            cJSON_Delete(array);
            return false;
        }
    }
    char* jsonStr = cJSON_Print(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return false;
    }
    policy = std::string(jsonStr);
    cJSON_free(jsonStr);
    cJSON_Delete(root);
    return true;
}

bool TelephonyCallPolicySerializer::GetPolicy(MessageParcel &data,
    std::map<std::string, TelephonyCallPolicyType> &result)
{
    return true;
}

bool TelephonyCallPolicySerializer::WritePolicy(MessageParcel &reply,
    std::map<std::string, TelephonyCallPolicyType> &result)
{
    return true;
}

bool TelephonyCallPolicySerializer::MergePolicy(std::vector<std::map<std::string, TelephonyCallPolicyType>> &data,
    std::map<std::string, TelephonyCallPolicyType> &result)
{
    for (auto policyMap : data) {
        for (auto iter : policyMap) {
            if (result.find(iter.first) == result.end()) {
                result[iter.first] = iter.second;
                continue;
            }
            std::unordered_set<std::string> uset;
            uset.insert(result[iter.first].numberList.begin(), result[iter.first].numberList.end());
            uset.insert(iter.second.numberList.begin(), iter.second.numberList.end());
            std::vector<std::string> mergeResult(uset.begin(), uset.end());
            result[iter.first].numberList = mergeResult;
            result[iter.first].policyFlag = iter.second.policyFlag;
        }
    }
    return true;
}
} // namespace EDM
} // namespace OHOS