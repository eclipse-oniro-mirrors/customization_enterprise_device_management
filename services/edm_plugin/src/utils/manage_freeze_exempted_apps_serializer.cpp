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

#include "manage_freeze_exempted_apps_serializer.h"
#include "edm_bundle_manager_impl.h"
#include <map>
#include "cJSON.h"
#include "cjson_check.h"

namespace OHOS {
namespace EDM {

const char* const BUNDLE_NAME = "bundleName";
const char* const ACCOUNT_ID = "accountId";
const char* const APP_INDEX = "appIndex";

std::vector<ManageFreezeExemptedAppInfo> ManageFreezeExemptedAppsSerializer::SetUnionPolicyData(
    std::vector<ManageFreezeExemptedAppInfo> &data, std::vector<ManageFreezeExemptedAppInfo> &currentData)
{
    std::vector<ManageFreezeExemptedAppInfo> mergeData;
    std::map<std::string, ManageFreezeExemptedAppInfo> mergeMap;
    for (ManageFreezeExemptedAppInfo &item : data) {
        std::string mergeKey = item.GetBundleName()
        + std::to_string(item.GetAccountId())
        + std::to_string(item.GetAppIndex());
        mergeMap[mergeKey] = item;
    }
    for (const ManageFreezeExemptedAppInfo &item : currentData) {
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

std::vector<ManageFreezeExemptedAppInfo> ManageFreezeExemptedAppsSerializer::SetDifferencePolicyData(
    std::vector<ManageFreezeExemptedAppInfo> &data, std::vector<ManageFreezeExemptedAppInfo> &currentData)
{
    std::vector<ManageFreezeExemptedAppInfo> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_difference(currentData.begin(), currentData.end(), data.begin(), data.end(), back_inserter(mergeData));
    return mergeData;
}

std::vector<ManageFreezeExemptedAppInfo> ManageFreezeExemptedAppsSerializer::SetNeedRemoveMergePolicyData(
    std::vector<ManageFreezeExemptedAppInfo> &mergeData, std::vector<ManageFreezeExemptedAppInfo> &data,
    std::vector<ApplicationMsg> &freezeExemptedApps)
{
    std::vector<ManageFreezeExemptedAppInfo> removeData;
    for (const ManageFreezeExemptedAppInfo &item : data) {
        if (std::find_if(mergeData.begin(), mergeData.end(), [&item](const ManageFreezeExemptedAppInfo &mergeItem) {
            return mergeItem.GetBundleName() == item.GetBundleName() &&
            mergeItem.GetAccountId() == item.GetAccountId() &&
            mergeItem.GetAppIndex() == item.GetAppIndex();
        }) == mergeData.end()) {
            ApplicationMsg instance;
            instance.bundleName = item.GetBundleName();
            instance.accountId = item.GetAccountId();
            instance.appIndex = item.GetAppIndex();
            freezeExemptedApps.push_back(instance);
            removeData.push_back(item);
        }
    }
    return removeData;
}

std::vector<ManageFreezeExemptedAppInfo> ManageFreezeExemptedAppsSerializer::SetIntersectionPolicyData(
    std::vector<ApplicationMsg> &freezeExemptedApps, std::vector<ManageFreezeExemptedAppInfo> &currentData)
{
    std::vector<ManageFreezeExemptedAppInfo> mergeData;
    for (const ApplicationMsg &dataItem : freezeExemptedApps) {
        for (const ManageFreezeExemptedAppInfo &item : currentData) {
            if (item.GetBundleName() == dataItem.bundleName && item.GetAppIndex() == dataItem.appIndex &&
                item.GetAccountId() == dataItem.accountId) {
                mergeData.push_back(item);
                break;
            }
        }
    }
    return mergeData;
}

bool ManageFreezeExemptedAppsSerializer::Deserialize(const std::string &policy,
    std::vector<ManageFreezeExemptedAppInfo> &dataObj)
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
        cJSON* accountId = cJSON_GetObjectItem(mapItem, ACCOUNT_ID);
        cJSON* appIndex = cJSON_GetObjectItem(mapItem, APP_INDEX);
        if (!cJSON_IsString(bundleName) || !cJSON_IsNumber(accountId) || !cJSON_IsNumber(appIndex)) {
            EDMLOGE("ManageFreezeExemptedAppsSerializer::Invalid data.");
            cJSON_Delete(root);
            return false;
        }
        ManageFreezeExemptedAppInfo appInfo;
        appInfo.SetBundleName(cJSON_GetStringValue(bundleName));
        appInfo.SetAccountId(cJSON_GetNumberValue(accountId));
        appInfo.SetAppIndex(cJSON_GetNumberValue(appIndex));
        dataObj.emplace_back(appInfo);
    }
    cJSON_Delete(root);
    return true;
}

bool ManageFreezeExemptedAppsSerializer::Serialize(const std::vector<ManageFreezeExemptedAppInfo> &dataObj,
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

bool ManageFreezeExemptedAppsSerializer::GetPolicy(MessageParcel &data,
    std::vector<ManageFreezeExemptedAppInfo> &result)
{
    uint32_t size = data.ReadUint32();
    if (size > EdmConstants::FREEZE_EXEMPTED_APPS_MAX_SIZE) {
        EDMLOGE("ManageFreezeExemptedAppsSerializer:GetPolicy size=[%{public}u] is too large", size);
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        ManageFreezeExemptedAppInfo info;
        if (!ManageFreezeExemptedAppInfo::Unmarshalling(data, info)) {
            EDMLOGE("ManageFreezeExemptedAppsSerializer GetDataByParcel::read parcel fail");
            return false;
        }
        result.emplace_back(info);
    }
    return true;
}

bool ManageFreezeExemptedAppsSerializer::WritePolicy(MessageParcel &reply,
    std::vector<ManageFreezeExemptedAppInfo> &result)
{
    return true;
}

bool ManageFreezeExemptedAppsSerializer::MergePolicy(std::vector<std::vector<ManageFreezeExemptedAppInfo>> &data,
    std::vector<ManageFreezeExemptedAppInfo> &result)
{
    std::set<ManageFreezeExemptedAppInfo> stData;
    std::map<std::string, ManageFreezeExemptedAppInfo> mapData;
    for (const auto &dataItem : data) {
        for (const ManageFreezeExemptedAppInfo &item : dataItem) {
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
} // namespace OHOS