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

#include "manage_apps_serializer.h"
#include "edm_bundle_manager_impl.h"
#include <map>
#include "cJSON.h"
#include "cjson_check.h"

namespace OHOS {
namespace EDM {

const char* const BUNDLE_NAME = "bundleName";
const char* const APP_IDENTIFIER = "appIdentifier";
const char* const ACCOUNT_ID = "accountId";
const char* const APP_INDEX = "appIndex";

std::vector<ApplicationInstance> ManageAppsSerializer::SetUnionPolicyData(std::vector<ApplicationInstance> &data,
    std::vector<ApplicationInstance> &currentData)
{
    std::vector<ApplicationInstance> mergeData;
    std::map<std::string, ApplicationInstance> mergeMap;
    for (const ApplicationInstance &item : data) {
        std::string mergeKey = item.bundleName + std::to_string(item.accountId) + std::to_string(item.appIndex);
        mergeMap[mergeKey] = item;
    }
    for (const ApplicationInstance &item : currentData) {
        std::string mergeKey = item.bundleName + std::to_string(item.accountId) + std::to_string(item.appIndex);
        mergeMap[mergeKey] = item;
    }
    for (const auto& pair : mergeMap) {
        mergeData.push_back(pair.second);
    }
    return mergeData;
}

std::vector<ApplicationInstance> ManageAppsSerializer::SetDifferencePolicyData(std::vector<ApplicationInstance> &data,
    std::vector<ApplicationInstance> &currentData)
{
    std::vector<ApplicationInstance> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_difference(currentData.begin(), currentData.end(), data.begin(), data.end(), back_inserter(mergeData));
    return mergeData;
}

std::vector<ApplicationInstance> ManageAppsSerializer::SetNeedRemoveMergePolicyData(
    std::vector<ApplicationInstance> &mergeData, std::vector<ApplicationInstance> &data)
{
    std::vector<ApplicationInstance> removeData;
    for (const ApplicationInstance &item : data) {
        if (std::find_if(mergeData.begin(), mergeData.end(), [&item](const ApplicationInstance &mergeItem) {
            return mergeItem.bundleName == item.bundleName &&
                mergeItem.accountId == item.accountId &&
                mergeItem.appIndex == item.appIndex;
        }) == mergeData.end()) {
            removeData.push_back(item);
        }
    }
    return removeData;
}

std::vector<ApplicationInstance> ManageAppsSerializer::SetIntersectionPolicyData(std::vector<ApplicationInstance> &data,
    std::vector<ApplicationInstance> &currentData)
{
    std::vector<ApplicationInstance> mergeData;
    for (const ApplicationInstance &dataItem : data) {
        for (const ApplicationInstance &item : currentData) {
            if (item.bundleName == dataItem.bundleName &&
                item.accountId == dataItem.accountId &&
                item.appIndex == dataItem.appIndex) {
                mergeData.push_back(item);
                break;
            }
        }
    }
    return mergeData;
}

bool ManageAppsSerializer::Deserialize(const std::string &policy, std::vector<ApplicationInstance> &dataObj)
{
    if (policy.empty()) {
        return true;
    }
    cJSON* root = cJSON_Parse(policy.c_str());
    if (root == nullptr) {
        return false;
    }
    if (!cJSON_IsArray(root)) {
        EDMLOGE("JSON root is not array");
        cJSON_Delete(root);
        return false;
    }
    cJSON* mapItem;
    cJSON_ArrayForEach(mapItem, root) {
        if (!cJSON_IsObject(mapItem)) {
            EDMLOGE("mapItem is not object");
            cJSON_Delete(root);
            return false;
        }
        cJSON* bundleName = cJSON_GetObjectItem(mapItem, BUNDLE_NAME);
        cJSON* appIdentifier = cJSON_GetObjectItem(mapItem, APP_IDENTIFIER);
        cJSON* accountId = cJSON_GetObjectItem(mapItem, ACCOUNT_ID);
        cJSON* appIndex = cJSON_GetObjectItem(mapItem, APP_INDEX);
        if (!cJSON_IsString(bundleName) || !cJSON_IsString(appIdentifier) ||
            !cJSON_IsNumber(accountId) || !cJSON_IsNumber(appIndex)) {
            EDMLOGE("ManageAppsSerializer::Invalid data.");
            cJSON_Delete(root);
            return false;
        }
        ApplicationInstance appInfo;
        appInfo.bundleName = cJSON_GetStringValue(bundleName);
        appInfo.appIdentifier = cJSON_GetStringValue(appIdentifier);
        appInfo.accountId = cJSON_GetNumberValue(accountId);
        appInfo.appIndex = cJSON_GetNumberValue(appIndex);
        dataObj.emplace_back(appInfo);
    }
    cJSON_Delete(root);
    return true;
}

bool ManageAppsSerializer::Serialize(const std::vector<ApplicationInstance> &dataObj, std::string &policy)
{
    if (dataObj.empty()) {
        return true;
    }
    cJSON* root = nullptr;
    CJSON_CREATE_ARRAY_AND_CHECK(root, false);
    for (auto& mapIt : dataObj) {
        cJSON* policyObject = nullptr;
        CJSON_CREATE_OBJECT_AND_CHECK_AND_CLEAR(policyObject, false, root);
        cJSON_AddStringToObject(policyObject, BUNDLE_NAME, mapIt.bundleName.c_str());
        cJSON_AddStringToObject(policyObject, APP_IDENTIFIER, mapIt.appIdentifier.c_str());
        cJSON_AddNumberToObject(policyObject, ACCOUNT_ID, mapIt.accountId);
        cJSON_AddNumberToObject(policyObject, APP_INDEX, mapIt.appIndex);
        if (!cJSON_AddItemToArray(root, policyObject)) {
            cJSON_Delete(root);
            cJSON_Delete(policyObject);
            return false;
        }
    }
    char *cJsonStr = cJSON_Print(root);
    if (cJsonStr != nullptr) {
        policy = std::string(cJsonStr);
        cJSON_free(cJsonStr);
    }
    cJSON_Delete(root);
    return true;
}

bool ManageAppsSerializer::GetPolicy(MessageParcel &data, std::vector<ApplicationInstance> &result)
{
    uint32_t size;
    if (!data.ReadUint32(size)) {
        return false;
    }
    if (size > EdmConstants::MANAGE_APPS_MAX_SIZE) {
        EDMLOGE("ManageAppsSerializer GetPolicy size=[%{public}u] is too large", size);
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        ApplicationInstance info;
        if (!ApplicationInstanceHandle::ReadApplicationInstance(data, info)) {
            EDMLOGE("ManageAppsSerializer GetDataByParcel::read parcel fail");
            return false;
        }
        result.emplace_back(info);
    }
    return true;
}

bool ManageAppsSerializer::WritePolicy(MessageParcel &reply, std::vector<ApplicationInstance> &result)
{
    return true;
}

std::string ManageAppsSerializer::MakeKey(const ApplicationInstance &item)
{
    return item.bundleName + "_" + std::to_string(item.accountId) + "_" + std::to_string(item.appIndex);
}

bool ManageAppsSerializer::MergePolicy(std::vector<std::vector<ApplicationInstance>> &data,
    std::vector<ApplicationInstance> &result)
{
    std::set<ApplicationInstance> stData;
    std::map<std::string, ApplicationInstance> mapData;
    for (const auto &dataItem : data) {
        for (const ApplicationInstance &item : dataItem) {
            std::string key = MakeKey(item);
            if (mapData.find(key) == mapData.end()) {
                mapData[key] = item;
                stData.insert(item);
            }
        }
    }
    result.assign(stData.begin(), stData.end());
    return true;
}
} // namespace EDM
} // namespace OHOS