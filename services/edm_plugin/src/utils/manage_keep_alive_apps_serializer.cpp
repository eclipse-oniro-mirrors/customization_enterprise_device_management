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

#include "manage_keep_alive_apps_serializer.h"

#include <map>
#include "cJSON.h"
#include "cjson_check.h"

namespace OHOS {
namespace EDM {

const char* const BUNDLE_NAME = "bundleName";
const char* const DISALLOW_MODIFY = "disallowModify";

std::vector<ManageKeepAliveAppInfo> ManageKeepAliveAppsSerializer::SetUnionPolicyData(
    std::vector<ManageKeepAliveAppInfo> &data, std::vector<ManageKeepAliveAppInfo> &currentData)
{
    std::vector<ManageKeepAliveAppInfo> mergeData;
    std::map<std::string, ManageKeepAliveAppInfo> mergeMap;
    for (ManageKeepAliveAppInfo &item : data) {
        mergeMap[item.GetBundleName()] = item;
    }
    for (const ManageKeepAliveAppInfo &item : currentData) {
        mergeMap[item.GetBundleName()] = item;
    }
    for (const auto& pair : mergeMap) {
        mergeData.push_back(pair.second);
    }
    return mergeData;
}

std::vector<ManageKeepAliveAppInfo> ManageKeepAliveAppsSerializer::SetDifferencePolicyData(
    std::vector<ManageKeepAliveAppInfo> &data, std::vector<ManageKeepAliveAppInfo> &currentData)
{
    std::vector<ManageKeepAliveAppInfo> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_difference(currentData.begin(), currentData.end(), data.begin(), data.end(), back_inserter(mergeData));
    return mergeData;
}

std::vector<ManageKeepAliveAppInfo> ManageKeepAliveAppsSerializer::SetNeedRemoveMergePolicyData(
    std::vector<ManageKeepAliveAppInfo> &mergeData, std::vector<ManageKeepAliveAppInfo> &data)
{
    std::vector<ManageKeepAliveAppInfo> removeData;
    for (const ManageKeepAliveAppInfo &item : data) {
        if (std::find_if(mergeData.begin(), mergeData.end(), [&item](const ManageKeepAliveAppInfo &mergeItem) {
            return mergeItem.GetBundleName() == item.GetBundleName();
        }) == mergeData.end()) {
            removeData.push_back(item);
        }
    }
    return removeData;
}

std::vector<ManageKeepAliveAppInfo> ManageKeepAliveAppsSerializer::SetIntersectionPolicyData(
    std::vector<std::string> &data, std::vector<ManageKeepAliveAppInfo> &currentData)
{
    std::vector<ManageKeepAliveAppInfo> mergeData;
    for (const std::string &dataItem : data) {
        for (const ManageKeepAliveAppInfo &item : currentData) {
            if (item.GetBundleName() == dataItem) {
                mergeData.push_back(item);
                break;
            }
        }
    }
    return mergeData;
}

bool ManageKeepAliveAppsSerializer::Deserialize(const std::string &policy, std::vector<ManageKeepAliveAppInfo> &dataObj)
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
        cJSON* disallowModify = cJSON_GetObjectItem(mapItem, DISALLOW_MODIFY);
        if (bundleName == nullptr && disallowModify == nullptr && cJSON_IsString(mapItem)) {
            bundleName = mapItem;
        } else if (!cJSON_IsString(bundleName) || !cJSON_IsBool(disallowModify)) {
            EDMLOGI("ManageKeepAliveAppsSerializer::cJSON_GetObjectItem get error type.");
            cJSON_Delete(root);
            return false;
        }
        ManageKeepAliveAppInfo appInfo;
        appInfo.SetBundleName(cJSON_GetStringValue(bundleName));
        appInfo.SetDisallowModify(disallowModify == nullptr ? true : cJSON_IsTrue(disallowModify));
        dataObj.emplace_back(appInfo);
    }
    cJSON_Delete(root);
    return true;
}

bool ManageKeepAliveAppsSerializer::Serialize(const std::vector<ManageKeepAliveAppInfo> &dataObj,
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
        cJSON_AddBoolToObject(policyObject, DISALLOW_MODIFY, mapIt.GetDisallowModify());
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

bool ManageKeepAliveAppsSerializer::GetPolicy(MessageParcel &data,
    std::vector<ManageKeepAliveAppInfo> &result)
{
    uint32_t size = data.ReadUint32();
    if (size > EdmConstants::KEEP_ALIVE_APPS_MAX_SIZE) {
        EDMLOGE("ManageKeepAliveAppsSerializer:GetPolicy size=[%{public}u] is too large", size);
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        ManageKeepAliveAppInfo info;
        if (!ManageKeepAliveAppInfo::Unmarshalling(data, info)) {
            EDMLOGE("ManageKeepAliveAppsSerializer GetDataByParcel::read parcel fail");
            return false;
        }
        result.emplace_back(info);
    }
    return true;
}

bool ManageKeepAliveAppsSerializer::WritePolicy(MessageParcel &reply,
    std::vector<ManageKeepAliveAppInfo> &result)
{
    return true;
}

bool ManageKeepAliveAppsSerializer::MergePolicy(std::vector<std::vector<ManageKeepAliveAppInfo>> &data,
    std::vector<ManageKeepAliveAppInfo> &result)
{
    std::set<ManageKeepAliveAppInfo> stData;
    std::map<std::string, ManageKeepAliveAppInfo> mapData;
    for (const auto &dataItem : data) {
        for (const ManageKeepAliveAppInfo &item : dataItem) {
            if (mapData.find(item.GetBundleName()) == mapData.end()) {
                mapData[item.GetBundleName()] = item;
                stData.insert(item);
            }
        }
    }
    result.assign(stData.begin(), stData.end());
    return true;
}

bool ManageKeepAliveAppsSerializer::UpdateByMergePolicy(std::vector<ManageKeepAliveAppInfo> &data,
    std::vector<ManageKeepAliveAppInfo> &mergeData)
{
    for (ManageKeepAliveAppInfo &dataItem : data) {
        for (const ManageKeepAliveAppInfo &mergeItem : mergeData) {
            if (dataItem.GetBundleName() == mergeItem.GetBundleName()) {
                dataItem.SetDisallowModify(mergeItem.GetDisallowModify());
                break;
            }
        }
    }
    return true;
}
} // namespace EDM
} //