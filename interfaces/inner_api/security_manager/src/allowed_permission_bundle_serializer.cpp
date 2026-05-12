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

#include "allowed_permission_bundle_serializer.h"

#include "application_instance.h"
#include "cJSON.h"
#include "cjson_check.h"
#include "edm_log.h"
#include "edm_constants.h"

namespace OHOS {
namespace EDM {

const char* const APP_IDENTIFIER = "appIdentifier";
const char* const APP_INDEX = "appIndex";
const char* const BUNDLE_NAME = "bundleName";
const char* const ACCOUNT_ID = "accountId";

std::string AllowedPermissionBundleSerializer::MakeKey(const ApplicationInstance &item)
{
    return item.appIdentifier + "_" + std::to_string(item.accountId) + "_" + std::to_string(item.appIndex);
}

bool AllowedPermissionBundleSerializer::IsAppInList(const ApplicationInstance &app,
    const std::vector<ApplicationInstance> &appList)
{
    for (const ApplicationInstance& item : appList) {
        if (app.appIdentifier == item.appIdentifier && app.appIndex == item.appIndex) {
            return true;
        }
    }
    return false;
}

std::vector<ApplicationInstance> AllowedPermissionBundleSerializer::GetAppsNotInList(
    const std::vector<ApplicationInstance> &sourceList,
    const std::vector<ApplicationInstance> &targetList)
{
    std::vector<ApplicationInstance> result;
    for (const ApplicationInstance& app : sourceList) {
        if (!IsAppInList(app, targetList)) {
            result.push_back(app);
        }
    }
    return result;
}

std::vector<ApplicationInstance> AllowedPermissionBundleSerializer::GetAppsInList(
    const std::vector<ApplicationInstance> &sourceList,
    const std::vector<ApplicationInstance> &targetList)
{
    std::vector<ApplicationInstance> result;
    for (const ApplicationInstance& app : sourceList) {
        if (IsAppInList(app, targetList)) {
            result.push_back(app);
        }
    }
    return result;
}

void AllowedPermissionBundleSerializer::AddAppToMergedMap(const std::string &permissionName,
    const std::vector<ApplicationInstance> &appList,
    std::map<std::string, std::map<std::string, ApplicationInstance>> &mergedData)
{
    for (const ApplicationInstance& appInfo : appList) {
        std::string appKey = MakeKey(appInfo);
        if (mergedData[permissionName].find(appKey) == mergedData[permissionName].end()) {
            mergedData[permissionName][appKey] = appInfo;
        }
    }
}

void AllowedPermissionBundleSerializer::MergePolicyDataIntoMap(
    const std::vector<std::map<std::string, std::vector<ApplicationInstance>>> &data,
    std::map<std::string, std::map<std::string, ApplicationInstance>> &mergedData)
{
    for (const auto& policyMap : data) {
        for (const auto& permissionPair : policyMap) {
            AddAppToMergedMap(permissionPair.first, permissionPair.second, mergedData);
        }
    }
}

std::map<std::string, std::vector<ApplicationInstance>> AllowedPermissionBundleSerializer::SetUnionPolicyData(
    std::map<std::string, std::vector<ApplicationInstance>> &data,
    std::map<std::string, std::vector<ApplicationInstance>> &currentData)
{
    std::map<std::string, std::map<std::string, ApplicationInstance>> mergedMap;

    for (const auto& permissionPair : data) {
        const std::string& permissionName = permissionPair.first;
        const std::vector<ApplicationInstance>& appList = permissionPair.second;

        for (const ApplicationInstance& item : appList) {
            std::string mergeKey = MakeKey(item);
            mergedMap[permissionName][mergeKey] = item;
        }
    }

    for (const auto& permissionPair : currentData) {
        const std::string& permissionName = permissionPair.first;
        const std::vector<ApplicationInstance>& appList = permissionPair.second;

        for (const ApplicationInstance& item : appList) {
            std::string mergeKey = MakeKey(item);
            mergedMap[permissionName][mergeKey] = item;
        }
    }

    std::map<std::string, std::vector<ApplicationInstance>> mergeData;
    for (const auto& permissionPair : mergedMap) {
        const std::string& permissionName = permissionPair.first;
        std::vector<ApplicationInstance> appList;

        for (const auto& appPair : permissionPair.second) {
            appList.push_back(appPair.second);
        }

        if (!appList.empty()) {
            mergeData[permissionName] = appList;
        }
    }

    return mergeData;
}

std::map<std::string, std::vector<ApplicationInstance>> AllowedPermissionBundleSerializer::SetDifferencePolicyData(
    std::map<std::string, std::vector<ApplicationInstance>> &data,
    std::map<std::string, std::vector<ApplicationInstance>> &currentData)
{
    std::map<std::string, std::vector<ApplicationInstance>> mergeData;

    for (const auto& permissionPair : currentData) {
        const std::string& permissionName = permissionPair.first;
        const std::vector<ApplicationInstance>& currentAppList = permissionPair.second;

        if (data.find(permissionName) == data.end()) {
            mergeData[permissionName] = currentAppList;
            continue;
        }

        std::vector<ApplicationInstance> resultList = GetAppsNotInList(currentAppList, data[permissionName]);
        if (!resultList.empty()) {
            mergeData[permissionName] = resultList;
        }
    }

    return mergeData;
}

std::map<std::string, std::vector<ApplicationInstance>> AllowedPermissionBundleSerializer::SetIntersectionPolicyData(
    std::map<std::string, std::vector<ApplicationInstance>> &data,
    std::map<std::string, std::vector<ApplicationInstance>> &currentData)
{
    std::map<std::string, std::vector<ApplicationInstance>> mergeData;

    for (const auto& permissionPair : data) {
        const std::string& permissionName = permissionPair.first;
        const std::vector<ApplicationInstance>& dataAppList = permissionPair.second;

        if (currentData.find(permissionName) == currentData.end()) {
            continue;
        }

        std::vector<ApplicationInstance> resultList = GetAppsInList(dataAppList, currentData[permissionName]);
        if (!resultList.empty()) {
            mergeData[permissionName] = resultList;
        }
    }

    return mergeData;
}

std::map<std::string, std::vector<ApplicationInstance>> AllowedPermissionBundleSerializer::SetNeedRemoveMergePolicyData(
    std::map<std::string, std::vector<ApplicationInstance>> &mergeData,
    std::map<std::string, std::vector<ApplicationInstance>> &data)
{
    std::map<std::string, std::vector<ApplicationInstance>> removeData;

    for (const auto& permissionPair : data) {
        const std::string& permissionName = permissionPair.first;
        const std::vector<ApplicationInstance>& dataAppList = permissionPair.second;

        if (mergeData.find(permissionName) == mergeData.end()) {
            if (!dataAppList.empty()) {
                removeData[permissionName] = dataAppList;
            }
            continue;
        }

        std::vector<ApplicationInstance> resultList = GetAppsNotInList(dataAppList, mergeData[permissionName]);
        if (!resultList.empty()) {
            removeData[permissionName] = resultList;
        }
    }

    return removeData;
}

bool AllowedPermissionBundleSerializer::Deserialize(const std::string &policy,
    std::map<std::string, std::vector<ApplicationInstance>> &dataObj)
{
    if (policy.empty()) {
        return true;
    }
    cJSON* root = cJSON_Parse(policy.c_str());
    if (root == nullptr) {
        EDMLOGE("AllowedPermissionBundleSerializer::Deserialize parse failed");
        return false;
    }
    if (!cJSON_IsObject(root)) {
        EDMLOGE("AllowedPermissionBundleSerializer::Deserialize root is not object");
        cJSON_Delete(root);
        return false;
    }

    cJSON* permissionItem = nullptr;
    cJSON_ArrayForEach(permissionItem, root) {
        std::string permissionName;
        std::vector<ApplicationInstance> appList;
        if (!ParsePermissionArray(permissionItem, permissionName, appList)) {
            cJSON_Delete(root);
            return false;
        }
        if (!appList.empty()) {
            dataObj[permissionName] = appList;
        }
    }

    cJSON_Delete(root);
    return true;
}

bool AllowedPermissionBundleSerializer::ParsePermissionArray(cJSON* permissionItem, std::string &permissionName,
    std::vector<ApplicationInstance> &appList)
{
    if (permissionItem == nullptr) {
        EDMLOGE("AllowedPermissionBundleSerializer::ParsePermissionArray permissionItem error");
        return false;
    }
    permissionName = permissionItem->string;
    if (!cJSON_IsArray(permissionItem)) {
        EDMLOGE("AllowedPermissionBundleSerializer::ParsePermissionArray permission value is not array");
        return false;
    }

    cJSON* appItem = nullptr;
    cJSON_ArrayForEach(appItem, permissionItem) {
        ApplicationInstance appInfo;
        if (!ParseAppItem(appItem, appInfo)) {
            return false;
        }
        appList.emplace_back(appInfo);
    }
    return true;
}

bool AllowedPermissionBundleSerializer::ParseAppItem(cJSON* appItem, ApplicationInstance &appInfo)
{
    if (!cJSON_IsObject(appItem)) {
        EDMLOGE("AllowedPermissionBundleSerializer::ParseAppItem appItem is not object");
        return false;
    }

    cJSON* appIdentifier = cJSON_GetObjectItem(appItem, APP_IDENTIFIER);
    cJSON* appIndex = cJSON_GetObjectItem(appItem, APP_INDEX);
    cJSON* accountId = cJSON_GetObjectItem(appItem, ACCOUNT_ID);
    cJSON* bundleName = cJSON_GetObjectItem(appItem, BUNDLE_NAME);

    if (!cJSON_IsString(appIdentifier) || !cJSON_IsNumber(appIndex)) {
        EDMLOGE("AllowedPermissionBundleSerializer::ParseAppItem invalid app data");
        return false;
    }

    appInfo.appIdentifier = cJSON_GetStringValue(appIdentifier);
    appInfo.appIndex = cJSON_GetNumberValue(appIndex);
    appInfo.accountId = (accountId != nullptr && cJSON_IsNumber(accountId)) ?
        static_cast<int32_t>(cJSON_GetNumberValue(accountId)) : 0;
    if (bundleName != nullptr && cJSON_IsString(bundleName)) {
        appInfo.bundleName = cJSON_GetStringValue(bundleName);
    } else {
        appInfo.bundleName = "";
    }
    return true;
}

bool AllowedPermissionBundleSerializer::Serialize(
    const std::map<std::string, std::vector<ApplicationInstance>> &dataObj, std::string &policy)
{
    if (dataObj.empty()) {
        return true;
    }

    cJSON* root = nullptr;
    CJSON_CREATE_OBJECT_AND_CHECK(root, false);

    for (const auto& permissionPair : dataObj) {
        if (permissionPair.second.empty()) {
            continue;
        }
        if (!SerializePermissionApps(permissionPair.first, permissionPair.second, root)) {
            cJSON_Delete(root);
            return false;
        }
    }

    char* cJsonStr = cJSON_Print(root);
    if (cJsonStr != nullptr) {
        policy = std::string(cJsonStr);
        cJSON_free(cJsonStr);
    }
    cJSON_Delete(root);
    return true;
}

bool AllowedPermissionBundleSerializer::SerializePermissionApps(const std::string &permissionName,
    const std::vector<ApplicationInstance> &appList, cJSON* root)
{
    cJSON* permissionArray = cJSON_CreateArray();
    if (permissionArray == nullptr) {
        EDMLOGE("AllowedPermissionBundleSerializer::SerializePermissionApps create array failed");
        return false;
    }

    for (const ApplicationInstance& appInfo : appList) {
        cJSON* appObject = CreateAppObject(appInfo);
        if (appObject == nullptr) {
            cJSON_Delete(permissionArray);
            return false;
        }
        if (!cJSON_AddItemToArray(permissionArray, appObject)) {
            cJSON_Delete(permissionArray);
            cJSON_Delete(appObject);
            return false;
        }
    }

    if (!cJSON_AddItemToObject(root, permissionName.c_str(), permissionArray)) {
        cJSON_Delete(permissionArray);
        return false;
    }
    return true;
}

cJSON* AllowedPermissionBundleSerializer::CreateAppObject(const ApplicationInstance &appInfo)
{
    cJSON* appObject = nullptr;
    CJSON_CREATE_OBJECT_AND_CHECK(appObject, nullptr);

    cJSON_AddStringToObject(appObject, APP_IDENTIFIER, appInfo.appIdentifier.c_str());
    cJSON_AddNumberToObject(appObject, ACCOUNT_ID, appInfo.accountId);
    cJSON_AddNumberToObject(appObject, APP_INDEX, appInfo.appIndex);
    cJSON_AddStringToObject(appObject, BUNDLE_NAME, appInfo.bundleName.c_str());

    return appObject;
}

bool AllowedPermissionBundleSerializer::GetPolicy(MessageParcel &data,
    std::map<std::string, std::vector<ApplicationInstance>> &result)
{
    uint32_t permissionCount = 0;
    if (!data.ReadUint32(permissionCount)) {
        EDMLOGE("AllowedPermissionBundleSerializer::GetPolicy read permissionCount failed");
        return false;
    }

    if (permissionCount > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
        EDMLOGE("AllowedPermissionBundleSerializer::GetPolicy size over max failed");
        return false;
    }

    for (uint32_t i = 0; i < permissionCount; i++) {
        std::string permissionName;
        if (!data.ReadString(permissionName)) {
            EDMLOGE("AllowedPermissionBundleSerializer::GetPolicy read permissionName failed");
            return false;
        }

        uint32_t appCount = 0;
        if (!data.ReadUint32(appCount)) {
            EDMLOGE("AllowedPermissionBundleSerializer::GetPolicy read appCount failed");
            return false;
        }
        if (appCount > EdmConstants::DEFAULT_LOOP_MAX_SIZE) {
            EDMLOGE("AllowedPermissionBundleSerializer::appCount size over max failed");
            return false;
        }

        std::vector<ApplicationInstance> appList;
        for (uint32_t j = 0; j < appCount; j++) {
            ApplicationInstance appInfo;
            if (!ApplicationInstanceHandle::ReadApplicationInstance(data, appInfo)) {
                EDMLOGE("AllowedPermissionBundleSerializer::GetPolicy read ApplicationInstance failed");
                return false;
            }
            appList.emplace_back(appInfo);
        }

        if (!appList.empty()) {
            result[permissionName] = appList;
        }
    }
    return true;
}

bool AllowedPermissionBundleSerializer::WritePolicy(MessageParcel &reply,
    std::map<std::string, std::vector<ApplicationInstance>> &result)
{
    uint32_t validPermissionCount = 0;
    for (const auto& permissionPair : result) {
        if (!permissionPair.second.empty()) {
            validPermissionCount++;
        }
    }

    if (!reply.WriteUint32(validPermissionCount)) {
        EDMLOGE("AllowedPermissionBundleSerializer::WritePolicy write permission count failed");
        return false;
    }

    for (const auto& permissionPair : result) {
        const std::vector<ApplicationInstance>& appList = permissionPair.second;

        if (appList.empty()) {
            continue;
        }

        if (!reply.WriteString(permissionPair.first)) {
            EDMLOGE("AllowedPermissionBundleSerializer::WritePolicy write permission name failed");
            return false;
        }

        if (!reply.WriteUint32(appList.size())) {
            EDMLOGE("AllowedPermissionBundleSerializer::WritePolicy write app count failed");
            return false;
        }

        for (const ApplicationInstance& appInfo : appList) {
            if (!ApplicationInstanceHandle::WriteApplicationInstance(reply, appInfo)) {
                EDMLOGE("AllowedPermissionBundleSerializer::WritePolicy write ApplicationInstance failed");
                return false;
            }
        }
    }
    return true;
}

bool AllowedPermissionBundleSerializer::MergePolicy(
    std::vector<std::map<std::string, std::vector<ApplicationInstance>>> &data,
    std::map<std::string, std::vector<ApplicationInstance>> &result)
{
    std::map<std::string, std::map<std::string, ApplicationInstance>> mergedData;
    MergePolicyDataIntoMap(data, mergedData);

    for (const auto& permissionPair : mergedData) {
        std::vector<ApplicationInstance> appList;
        for (const auto& appPair : permissionPair.second) {
            appList.emplace_back(appPair.second);
        }
        if (!appList.empty()) {
            result[permissionPair.first] = appList;
        }
    }

    return true;
}

} // namespace EDM
} // namespace OHOS