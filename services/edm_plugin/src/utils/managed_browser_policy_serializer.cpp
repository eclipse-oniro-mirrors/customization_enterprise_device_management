/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "managed_browser_policy_serializer.h"

#include "cJSON.h"
#include "cjson_check.h"

namespace OHOS {
namespace EDM {

const char* const VERSION = "version";
const char* const POLICY_NAMES = "policyNames";
const char* const OWNERSHIP = "ownership";
const char* const ADMIN_BUNDLE_NAME = "adminBundleName";
const char* const IS_FORCE_OVERRIDE = "isForceOverride";

bool ManagedBrowserPolicySerializer::Deserialize(const std::string &policy,
    std::map<std::string, ManagedBrowserPolicyType> &dataObj)
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
        cJSON* version = cJSON_GetObjectItem(mapItem, VERSION);
        cJSON* policyNames = cJSON_GetObjectItem(mapItem, POLICY_NAMES);
        if (!cJSON_IsArray(policyNames) || !cJSON_IsNumber(version)) {
            cJSON_Delete(root);
            return false;
        }
        std::vector<std::string> policyVector;
        cJSON* vectorItem;
        cJSON_ArrayForEach(vectorItem, policyNames) {
            char* policyValue = cJSON_GetStringValue(vectorItem);
            if (policyValue == nullptr) {
                cJSON_Delete(root);
                return false;
            }
            policyVector.push_back(std::string(policyValue));
        }
        dataObj[mapItem->string].policyNames = policyVector;
        dataObj[mapItem->string].version = version->valueint;
        DeserializeOwnership(mapItem, dataObj[mapItem->string]);
    }
    cJSON_Delete(root);
    return true;
}

void ManagedBrowserPolicySerializer::DeserializeOwnership(cJSON* mapItem, ManagedBrowserPolicyType &policyType)
{
    cJSON* ownership = cJSON_GetObjectItem(mapItem, OWNERSHIP);
    if (!cJSON_IsObject(ownership)) {
        return;
    }
    cJSON* ownershipItem;
    cJSON_ArrayForEach(ownershipItem, ownership) {
        if (ownershipItem->string == nullptr) {
            continue;
        }
        cJSON* adminName = cJSON_GetObjectItem(ownershipItem, ADMIN_BUNDLE_NAME);
        cJSON* isForce = cJSON_GetObjectItem(ownershipItem, IS_FORCE_OVERRIDE);
        if (!cJSON_IsString(adminName) || !cJSON_IsBool(isForce)) {
            continue;
        }
        ManagedBrowserPolicyOwnership owner;
        owner.adminBundleName = std::string(adminName->valuestring);
        owner.isForceOverride = cJSON_IsTrue(isForce);
        policyType.ownership[std::string(ownershipItem->string)] = owner;
    }
}

bool ManagedBrowserPolicySerializer::Serialize(const std::map<std::string, ManagedBrowserPolicyType> &dataObj,
    std::string &policy)
{
    cJSON* root = nullptr;
    CJSON_CREATE_OBJECT_AND_CHECK(root, false);
    for (auto& mapIt : dataObj) {
        cJSON* policyObject = nullptr;
        CJSON_CREATE_OBJECT_AND_CHECK_AND_CLEAR(policyObject, false, root);
        cJSON_AddNumberToObject(policyObject, VERSION, mapIt.second.version);
        cJSON* array = cJSON_CreateArray();
        if (array == nullptr) {
            cJSON_Delete(root);
            cJSON_Delete(policyObject);
            return false;
        }
        for (auto& vectorIt : mapIt.second.policyNames) {
            cJSON* policyValue = cJSON_CreateString(vectorIt.c_str());
            if (policyValue == nullptr) {
                cJSON_Delete(root);
                cJSON_Delete(policyObject);
                cJSON_Delete(array);
                return false;
            }
            cJSON_AddItemToArray(array, policyValue);
        }
        if (!cJSON_AddItemToObject(policyObject, POLICY_NAMES, array)) {
            cJSON_Delete(root);
            cJSON_Delete(policyObject);
            cJSON_Delete(array);
            return false;
        }
        if (!SerializeOwnership(mapIt.second, policyObject)) {
            cJSON_Delete(root);
            cJSON_Delete(policyObject);
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

bool ManagedBrowserPolicySerializer::SerializeOwnership(const ManagedBrowserPolicyType &policyType,
    cJSON* policyObject)
{
    if (policyType.ownership.empty()) {
        return true;
    }
    cJSON* ownership = cJSON_CreateObject();
    if (ownership == nullptr) {
        return false;
    }
    for (auto& ownerIt : policyType.ownership) {
        cJSON* ownerObject = cJSON_CreateObject();
        if (ownerObject == nullptr) {
            cJSON_Delete(ownership);
            return false;
        }
        cJSON_AddStringToObject(ownerObject, ADMIN_BUNDLE_NAME, ownerIt.second.adminBundleName.c_str());
        cJSON_AddBoolToObject(ownerObject, IS_FORCE_OVERRIDE, ownerIt.second.isForceOverride);
        if (!cJSON_AddItemToObject(ownership, ownerIt.first.c_str(), ownerObject)) {
            cJSON_Delete(ownerObject);
            cJSON_Delete(ownership);
            return false;
        }
    }
    if (!cJSON_AddItemToObject(policyObject, OWNERSHIP, ownership)) {
        cJSON_Delete(ownership);
        return false;
    }
    return true;
}

bool ManagedBrowserPolicySerializer::GetPolicy(MessageParcel &data,
    std::map<std::string, ManagedBrowserPolicyType> &result)
{
    return true;
}

bool ManagedBrowserPolicySerializer::WritePolicy(MessageParcel &reply,
    std::map<std::string, ManagedBrowserPolicyType> &result)
{
    return true;
}

bool ManagedBrowserPolicySerializer::MergePolicy(std::vector<std::map<std::string, ManagedBrowserPolicyType>> &data,
    std::map<std::string, ManagedBrowserPolicyType> &result)
{
    return true;
}
} // namespace EDM
} // namespace OHOS