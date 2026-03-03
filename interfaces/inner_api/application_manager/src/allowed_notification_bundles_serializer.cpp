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

#include "allowed_notification_bundles_serializer.h"

#include "cJSON.h"
#include "cjson_check.h"

namespace OHOS {
namespace EDM {

const char* const USER_ID = "userId";
const char* const TRUST_LIST = "trustList";

bool AllowedNotificationBundlesSerializer::Deserialize(const std::string &policy,
    std::vector<AllowedNotificationBundlesType> &dataObj)
{
    if (policy.empty()) {
        return true;
    }
    cJSON* root = cJSON_Parse(policy.c_str());
    if (root == nullptr) {
        return false;
    }
    cJSON* item;
    cJSON_ArrayForEach(item, root) {
        cJSON* userId = cJSON_GetObjectItem(item, USER_ID);
        cJSON* trustList = cJSON_GetObjectItem(item, TRUST_LIST);
        if (userId == nullptr || trustList == nullptr || !cJSON_IsNumber(userId) || !cJSON_IsArray(trustList)) {
            cJSON_Delete(root);
            return false;
        }
        AllowedNotificationBundlesType bundlesType;
        bundlesType.userId = userId->valueint;
        cJSON* bundleItem;
        cJSON_ArrayForEach(bundleItem, trustList) {
            if (cJSON_IsString(bundleItem)) {
                bundlesType.trustList.insert(cJSON_GetStringValue(bundleItem));
            }
        }
        dataObj.push_back(bundlesType);
    }
    cJSON_Delete(root);
    return true;
}

bool AllowedNotificationBundlesSerializer::Serialize(const std::vector<AllowedNotificationBundlesType> &dataObj,
    std::string &policy)
{
    if (dataObj.empty()) {
        return true;
    }
    cJSON* root = nullptr;
    CJSON_CREATE_ARRAY_AND_CHECK(root, false);
    for (const auto& item : dataObj) {
        cJSON* obj = nullptr;
        CJSON_CREATE_OBJECT_AND_CHECK_AND_CLEAR(obj, false, root);
        cJSON_AddNumberToObject(obj, USER_ID, item.userId);
        if (!CreateTrustListArray(obj, item.trustList)) {
            cJSON_Delete(obj);
            cJSON_Delete(root);
            return false;
        }
        if (!cJSON_AddItemToArray(root, obj)) {
            cJSON_Delete(obj);
            cJSON_Delete(root);
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

bool AllowedNotificationBundlesSerializer::CreateTrustListArray(cJSON* obj, const std::set<std::string> &trustList)
{
    cJSON* trustListArray = cJSON_CreateArray();
    if (trustListArray == nullptr) {
        return false;
    }
    for (const auto& bundleName : trustList) {
        cJSON* bundleItem = cJSON_CreateString(bundleName.c_str());
        if (bundleItem == nullptr) {
            cJSON_Delete(trustListArray);
            return false;
        }
        if (!cJSON_AddItemToArray(trustListArray, bundleItem)) {
            cJSON_Delete(bundleItem);
            cJSON_Delete(trustListArray);
            return false;
        }
    }
    if (!cJSON_AddItemToObject(obj, TRUST_LIST, trustListArray)) {
        cJSON_Delete(trustListArray);
        return false;
    }
    return true;
}

bool AllowedNotificationBundlesSerializer::GetPolicy(MessageParcel &data,
    std::vector<AllowedNotificationBundlesType> &result)
{
    AllowedNotificationBundlesType type;
    std::vector<std::string> trustList;
    data.ReadStringVector(&trustList);
    type.trustList.insert(trustList.begin(), trustList.end());
    type.userId = data.ReadInt32();
    result.push_back(type);
    return true;
}

bool AllowedNotificationBundlesSerializer::WritePolicy(MessageParcel &reply,
    std::vector<AllowedNotificationBundlesType> &result)
{
    return true;
}

bool AllowedNotificationBundlesSerializer::MergePolicy(
    std::vector<std::vector<AllowedNotificationBundlesType>> &data,
    std::vector<AllowedNotificationBundlesType> &result)
{
    if (!data.empty()) {
        result.clear();
        std::map<int32_t, std::set<std::string>> mergedData;
        
        for (const auto& adminData : data) {
            for (const auto& item : adminData) {
                mergedData[item.userId].insert(item.trustList.begin(), item.trustList.end());
            }
        }
        
        for (const auto& [userId, trustList] : mergedData) {
            AllowedNotificationBundlesType bundleType;
            bundleType.userId = userId;
            bundleType.trustList = trustList;
            result.push_back(bundleType);
        }
    }
    return true;
}

} // namespace EDM
} // namespace OHOS
