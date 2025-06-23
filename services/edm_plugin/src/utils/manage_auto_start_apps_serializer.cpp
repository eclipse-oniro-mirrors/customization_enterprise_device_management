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
 
#include "manage_auto_start_apps_serializer.h"
 
#include <map>
#include "cJSON.h"
#include "cjson_check.h"
 
namespace OHOS {
namespace EDM {
 
const char* const BUNDLE_NAME = "bundleName";
const char* const ABILITY_NAME = "abilityName";
const char* const DISALLOW_MODIFY = "disallowModify";
 
std::vector<ManageAutoStartAppInfo> ManageAutoStartAppsSerializer::SetUnionPolicyData(
    std::vector<ManageAutoStartAppInfo> &data, std::vector<ManageAutoStartAppInfo> &currentData)
{
    std::vector<ManageAutoStartAppInfo> mergeData;
    std::map<std::string, ManageAutoStartAppInfo> mergeMap;
    for (ManageAutoStartAppInfo &item : data) {
        mergeMap[item.GetUniqueKey()] = item;
    }
    for (const ManageAutoStartAppInfo &item : currentData) {
        mergeMap[item.GetUniqueKey()] = item;
    }
    for (const auto& pair : mergeMap) {
        mergeData.push_back(pair.second);
    }
    return mergeData;
}
 
std::vector<ManageAutoStartAppInfo> ManageAutoStartAppsSerializer::SetDifferencePolicyData(
    std::vector<ManageAutoStartAppInfo> &data, std::vector<ManageAutoStartAppInfo> &currentData)
{
    std::vector<ManageAutoStartAppInfo> mergeData;
    std::sort(data.begin(), data.end());
    std::sort(currentData.begin(), currentData.end());
    std::set_difference(currentData.begin(), currentData.end(), data.begin(), data.end(), back_inserter(mergeData));
    return mergeData;
}
 
std::vector<ManageAutoStartAppInfo> ManageAutoStartAppsSerializer::SetNeedRemoveMergePolicyData(
    std::vector<ManageAutoStartAppInfo> &mergeData, std::vector<ManageAutoStartAppInfo> &data)
{
    std::vector<ManageAutoStartAppInfo> removeData;
    for (const ManageAutoStartAppInfo &item : data) {
        if (std::find_if(mergeData.begin(), mergeData.end(), [&item](const ManageAutoStartAppInfo &mergeItem) {
            return mergeItem.GetUniqueKey() == item.GetUniqueKey();
        }) == mergeData.end()) {
            removeData.push_back(item);
        }
    }
    return removeData;
}
 
std::vector<ManageAutoStartAppInfo> ManageAutoStartAppsSerializer::SetIntersectionPolicyData(
    std::vector<std::string> &data, std::vector<ManageAutoStartAppInfo> &currentData)
{
    std::vector<ManageAutoStartAppInfo> mergeData;
    for (const std::string &dataItem : data) {
        for (const ManageAutoStartAppInfo &item : currentData) {
            if (item.GetUniqueKey() == dataItem) {
                mergeData.push_back(item);
                break;
            }
        }
    }
    return mergeData;
}
 
bool ManageAutoStartAppsSerializer::Deserialize(const std::string &policy, std::vector<ManageAutoStartAppInfo> &dataObj)
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
        cJSON* abilityName = cJSON_GetObjectItem(mapItem, ABILITY_NAME);
        cJSON* disallowModify = cJSON_GetObjectItem(mapItem, DISALLOW_MODIFY);
        ManageAutoStartAppInfo appInfo;
        if (bundleName == nullptr && disallowModify == nullptr && abilityName == nullptr) {
            std::string autoStartString = cJSON_GetStringValue(mapItem);
            size_t index = autoStartString.find("/");
            if (index != autoStartString.npos) {
                appInfo.SetBundleName(autoStartString.substr(0, index));
                appInfo.SetAbilityName(autoStartString.substr(index + 1));
                appInfo.SetDisallowModify(false);
                dataObj.emplace_back(appInfo);
            } else {
                EDMLOGE("ManageAutoStartAppsSerializer parse auto start app want failed");
                cJSON_Delete(root);
                return false;
            }
        } else if (!cJSON_IsString(bundleName) || !cJSON_IsBool(disallowModify) || !cJSON_IsString(abilityName)) {
            EDMLOGI("ManageAutoStartAppsSerializer::cJSON_GetObjectItem get error type.");
            cJSON_Delete(root);
            return false;
        } else {
            appInfo.SetBundleName(cJSON_GetStringValue(bundleName));
            appInfo.SetAbilityName(cJSON_GetStringValue(abilityName));
            appInfo.SetDisallowModify(cJSON_IsTrue(disallowModify));
            dataObj.emplace_back(appInfo);
        }
    }
    cJSON_Delete(root);
    return true;
}
 
bool ManageAutoStartAppsSerializer::Serialize(const std::vector<ManageAutoStartAppInfo> &dataObj,
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
        cJSON_AddStringToObject(policyObject, ABILITY_NAME, mapIt.GetAbilityName().c_str());
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
        EDMLOGI("ManageAutoStartAppsSerializer::Serialize : %{public}s.", policy.c_str());
        cJSON_free(cJsonStr);
    }
    cJSON_Delete(root);
    return true;
}
 
bool ManageAutoStartAppsSerializer::GetPolicy(MessageParcel &data,
    std::vector<ManageAutoStartAppInfo> &result)
{
    uint32_t size = data.ReadUint32();
    if (size > EdmConstants::AUTO_START_APPS_MAX_SIZE) {
        EDMLOGE("ManageAutoStartAppsSerializer:GetPolicy size=[%{public}u] is too large", size);
        return false;
    }
    for (uint32_t i = 0; i < size; i++) {
        ManageAutoStartAppInfo info;
        if (!ManageAutoStartAppInfo::Unmarshalling(data, info)) {
            EDMLOGE("ManageAutoStartAppsSerializer GetDataByParcel::read parcel fail");
            return false;
        }
        result.emplace_back(info);
    }
    return true;
}
 
bool ManageAutoStartAppsSerializer::WritePolicy(MessageParcel &reply,
    std::vector<ManageAutoStartAppInfo> &result)
{
    return true;
}
 
bool ManageAutoStartAppsSerializer::MergePolicy(std::vector<std::vector<ManageAutoStartAppInfo>> &data,
    std::vector<ManageAutoStartAppInfo> &result)
{
    std::set<ManageAutoStartAppInfo> stData;
    std::map<std::string, ManageAutoStartAppInfo> mapData;
    for (const auto &dataItem : data) {
        for (const ManageAutoStartAppInfo &item : dataItem) {
            if (mapData.find(item.GetUniqueKey()) == mapData.end()) {
                mapData[item.GetUniqueKey()] = item;
                stData.insert(item);
            }
        }
    }
    result.assign(stData.begin(), stData.end());
    return true;
}
 
bool ManageAutoStartAppsSerializer::UpdateByMergePolicy(std::vector<ManageAutoStartAppInfo> &data,
    std::vector<ManageAutoStartAppInfo> &mergeData)
{
    for (ManageAutoStartAppInfo &dataItem : data) {
        for (const ManageAutoStartAppInfo &mergeItem : mergeData) {
            if (dataItem.GetUniqueKey() == mergeItem.GetUniqueKey()) {
                dataItem.SetDisallowModify(mergeItem.GetDisallowModify());
                break;
            }
        }
    }
    return true;
}
} // namespace EDM
} //