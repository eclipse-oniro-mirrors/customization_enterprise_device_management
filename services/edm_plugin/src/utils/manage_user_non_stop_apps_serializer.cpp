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

#include "manage_user_non_stop_apps_serializer.h"

#include <map>
#include "cJSON.h"
#include "cjson_check.h"
#include "edm_bundle_manager_impl.h"

namespace OHOS {
namespace EDM {

const char* const BUNDLE_NAME = "bundleName";
const char* const ACCOUNT_ID = "accountId";
const char* const APP_INDEX = "appIndex";

std::vector<ManageUserNonStopAppInfo> ManageUserNonStopAppsSerializer::SetUnionPolicyData(
    std::vector<ManageUserNonStopAppInfo> &data, std::vector<ManageUserNonStopAppInfo> &currentData)
{
    std::vector<ManageUserNonStopAppInfo> mergeData;
    std::map<std::string, ManageUserNonStopAppInfo> mergeMap;
    for (ManageUserNonStopAppInfo &item : data) {
        std::string mergeKey = item.GetBundleName()
            + std::to_string(item.GetAccountId())
            + std::to_string(item.GetAppIndex());
        mergeMap[mergeKey] = item;
    }
    for (const ManageUserNonStopAppInfo &item : currentData) {
        std::string mergeKey = item.GetBundleName()
            + std::to_string(item.GetAccountId())
            + std::to_string(item.GetAppIndex());
        mergeMap[mergeKey] = item;
    }
    for (const auto& pair : mergeMap) {
        mergeData.push_back(pair.second);
    }
    return mergeData;
}

std::vector<ManageUserNonStopAppInfo> ManageUserNonStopAppsSerializer::SetDifferencePolicyData(
    std::vector<ManageUserNonStopAppInfo> &data, std::vector<ManageUserNonStopAppInfo> &currentData)
{
    std::vector<ManageUserNonStopAppInfo> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_difference(currentData.begin(), currentData.end(), data.begin(), data.end(), back_inserter(mergeData));
    return mergeData;
}

std::vector<ManageUserNonStopAppInfo> ManageUserNonStopAppsSerializer::SetNeedRemoveMergePolicyData(
    std::vector<ManageUserNonStopAppInfo> &mergeData, std::vector<ManageUserNonStopAppInfo> &data)
{
    std::vector<ManageUserNonStopAppInfo> removeData;
    for (const ManageUserNonStopAppInfo &item : data) {
        if (std::find_if(mergeData.begin(), mergeData.end(), [&item](const ManageUserNonStopAppInfo &mergeItem) {
            return mergeItem.GetBundleName() == item.GetBundleName() &&
                    mergeItem.GetAccountId() == item.GetAccountId() &&
                    mergeItem.GetAppIndex() == item.GetAppIndex();
        }) == mergeData.end()) {
            removeData.push_back(item);
        }
    }
    return removeData;
}

std::vector<ManageUserNonStopAppInfo> ManageUserNonStopAppsSerializer::SetIntersectionPolicyData(
    std::vector<ApplicationMsg> &data, std::vector<ManageUserNonStopAppInfo> &currentData)
{
    std::vector<ManageUserNonStopAppInfo> mergeData;
    for (const ApplicationMsg &dataItem : data) {
        for (const ManageUserNonStopAppInfo &item : currentData) {
            if (item.GetBundleName() == dataItem.bundleName &&
                item.GetAccountId() == dataItem.accountId &&
                item.GetAppIndex() == dataItem.appIndex) {
                mergeData.push_back(item);
                break;
            }
        }
    }
    return mergeData;
}

bool ManageUserNonStopAppsSerializer::Deserialize(const std::string &policy,
    std::vector<ManageUserNonStopAppInfo> &dataObj)
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
        cJSON* bundleName = cJSON_GetObjectItem(mapItem, BUNDLE_NAME);
        cJSON* accountId = cJSON_GetObjectItem(mapItem, ACCOUNT_ID);
        cJSON* appIndex = cJSON_GetObjectItem(mapItem, APP_INDEX);
        if (bundleName == nullptr && cJSON_IsString(mapItem)) {
            bundleName = mapItem;
        } else if (!cJSON_IsString(bundleName)) {
            EDMLOGI("ManageUserNonStopAppsSerializer::cJSON_GetObjectItem get error type.");
            cJSON_Delete(root);
            return false;
        }
        ManageUserNonStopAppInfo appInfo;
        appInfo.SetBundleName(cJSON_GetStringValue(bundleName));
        appInfo.SetAccountId(cJSON_GetNumberValue(accountId));
        appInfo.SetAppIndex(cJSON_GetNumberValue(appIndex));
        dataObj.emplace_back(appInfo);
    }
    cJSON_Delete(root);
    return true;
}

bool ManageUserNonStopAppsSerializer::Serialize(const std::vector<ManageUserNonStopAppInfo> &dataObj,
    std::string &policy)
{
    if (dataObj.empty()) {
        return true;
    }
    cJSON* root = nullptr;
    CJSON_CREATE_OBJECT_AND_CHECK(root, false);
    for (auto& mapIt : dataObj) {
        cJSON* policyObject = nullptr;
        CJSON_CREATE_OBJECT_AND_CHECK_AND_CLEAR(policyObject, false, root);
        cJSON_AddStringToObject(policyObject, BUNDLE_NAME, mapIt.GetBundleName().c_str());
        cJSON_AddNumberToObject(policyObject, ACCOUNT_ID, mapIt.GetAccountId());
        cJSON_AddNumberToObject(policyObject, APP_INDEX, mapIt.GetAppIndex());
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

bool ManageUserNonStopAppsSerializer::GetPolicy(MessageParcel &data,
    std::vector<ManageUserNonStopAppInfo> &result)
{
    uint32_t size = data.ReadUint32();
    if (size > EdmConstants::USER_NON_STOP_APPS_MAX_SIZE) {
        EDMLOGE("ManageUserNonStopAppsSerializer:GetPolicy size=[%{public}u] is too large", size);
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        ManageUserNonStopAppInfo info;
        if (!ManageUserNonStopAppInfo::Unmarshalling(data, info)) {
            EDMLOGE("ManageUserNonStopAppsSerializer GetDataByParcel::read parcel fail");
            return false;
        }
        result.emplace_back(info);
    }
    return true;
}

bool ManageUserNonStopAppsSerializer::WritePolicy(MessageParcel &reply,
    std::vector<ManageUserNonStopAppInfo> &result)
{
    return true;
}

bool ManageUserNonStopAppsSerializer::MergePolicy(std::vector<std::vector<ManageUserNonStopAppInfo>> &data,
    std::vector<ManageUserNonStopAppInfo> &result)
{
    std::set<ManageUserNonStopAppInfo> stData;
    std::map<std::string, ManageUserNonStopAppInfo> mapData;
    for (const auto &dataItem : data) {
        for (const ManageUserNonStopAppInfo &item : dataItem) {
            if (mapData.find(item.GetBundleName()) == mapData.end()) {
                mapData[item.GetBundleName()] = item;
                stData.insert(item);
            }
        }
    }
    result.assign(stData.begin(), stData.end());
    return true;
}
} // namespace EDM
} //