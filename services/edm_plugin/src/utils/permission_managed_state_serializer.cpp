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

#include "permission_managed_state_serializer.h"

#include <sstream>

#include "accesstoken_kit.h"
#include "cJSON.h"

#include "cjson_check.h"
#include "edm_access_token_manager_impl.h"
#include "edm_log.h"
#include "edm_sys_manager.h"

namespace OHOS {
namespace EDM {

const std::string APP_ID = "appId";
const std::string PERMISSION_NAME = "permissionName";
const std::string PERMISSION_NAMES = "permissionNames";
const std::string ACCOUNT_ID = "accountId";
const std::string APP_INDEX = "appIndex";
const std::string MANAGED_STATE = "managedState";
const std::string TOKEN_ID = "tokenId";

bool PermissionManagedStateSerializer::Deserialize(const std::string &data,
    std::map<std::string, PermissionManagedStateInfo> &result)
{
    cJSON* root = cJSON_Parse(data.c_str());
    if (root == nullptr) {
        return true;
    }
    cJSON* item;
    cJSON_ArrayForEach(item, root) {
        cJSON* appId = cJSON_GetObjectItem(item, APP_ID.c_str());
        cJSON* accountId = cJSON_GetObjectItem(item, ACCOUNT_ID.c_str());
        cJSON* appIndex = cJSON_GetObjectItem(item, APP_INDEX.c_str());
        cJSON* managedState = cJSON_GetObjectItem(item, MANAGED_STATE.c_str());
        cJSON* permissionName = cJSON_GetObjectItem(item, PERMISSION_NAME.c_str());
        cJSON* permissionNames = cJSON_GetObjectItem(item, PERMISSION_NAMES.c_str());
        cJSON* tokenId = cJSON_GetObjectItem(item, TOKEN_ID.c_str());
        if (managedState == nullptr || appId == nullptr || permissionNames == nullptr ||
            accountId == nullptr || appIndex == nullptr || permissionName == nullptr || tokenId == nullptr ||
            !cJSON_IsNumber(managedState) || !cJSON_IsString(appId) || !cJSON_IsArray(permissionNames) ||
            !cJSON_IsNumber(accountId) || !cJSON_IsNumber(appIndex) || !cJSON_IsString(permissionName) ||
            !cJSON_IsNumber(tokenId)) {
            cJSON_Delete(root);
            return false;
        }

        PermissionManagedStateInfo info;
        info.appId = appId->valuestring;
        info.accountId = accountId->valueint;
        info.appIndex = appIndex->valueint;
        info.managedState = managedState->valueint;
        info.permissionName = permissionName->valuestring;
        info.tokenId = tokenId->valueint;

        std::stringstream appPermissionKey;
        appPermissionKey << info.tokenId <<"\t"<< info.permissionName;
        std::string appPermissionKeyStr = appPermissionKey.str();

        result.insert(std::make_pair(appPermissionKeyStr, info));
    }
    cJSON_Delete(root);
    return true;
}

bool PermissionManagedStateSerializer::Serialize(const std::map<std::string, PermissionManagedStateInfo> &result,
    std::string &data)
{
    if (result.empty()) {
        return true;
    }
    cJSON* root = nullptr;
    CJSON_CREATE_ARRAY_AND_CHECK(root, false);
    for (auto& it : result) {
        cJSON* item = nullptr;
        CJSON_CREATE_OBJECT_AND_CHECK_AND_CLEAR(item, false, root);
        cJSON_AddItemToArray(root, item);
        cJSON_AddStringToObject(item, APP_ID.c_str(), it.second.appId.c_str());
        cJSON_AddStringToObject(item, PERMISSION_NAME.c_str(), it.second.permissionName.c_str());
        cJSON_AddNumberToObject(item, ACCOUNT_ID.c_str(), it.second.accountId);
        cJSON_AddNumberToObject(item, APP_INDEX.c_str(), it.second.appIndex);
        cJSON_AddNumberToObject(item, MANAGED_STATE.c_str(), it.second.managedState);
        cJSON_AddNumberToObject(item, TOKEN_ID.c_str(), it.second.tokenId);
        cJSON *permissionNames = cJSON_CreateArray();
        if (permissionNames == nullptr) {
            cJSON_Delete(root);
            return false;
        }
        for (std::string permissionName: it.second.permissionNames) {
            cJSON* permissionNameItem = cJSON_CreateString(permissionName.c_str());
            if (permissionNameItem == nullptr) {
                cJSON_Delete(root);
                cJSON_Delete(permissionNames);
                return false;
            }
            cJSON_AddItemToArray(permissionNames, permissionNameItem);
        }
        if (!cJSON_AddItemToObject(item, PERMISSION_NAMES.c_str(), permissionNames)) {
            cJSON_Delete(root);
            cJSON_Delete(permissionNames);
            return false;
        }
    }
    char* jsonStr = cJSON_Print(root);
    if (jsonStr == nullptr) {
        cJSON_Delete(root);
        return false;
    }
    data = std::string(jsonStr);
    cJSON_free(jsonStr);
    cJSON_Delete(root);
    return true;
}

bool PermissionManagedStateSerializer::GetPolicy(MessageParcel &data,
    std::map<std::string, PermissionManagedStateInfo> &result)
{
    PermissionManagedStateInfo info;
    info.appId = data.ReadString();
    info.accountId = data.ReadInt32();
    info.appIndex = data.ReadInt32();
    if (!data.ReadStringVector(&info.permissionNames)) {
        EDMLOGE("PermissionManagedStateSerializer GetPolicy params error.");
        return false;
    }
    info.managedState = data.ReadInt32();
    Security::AccessToken::AccessTokenID accessTokenId;
    EdmAccessTokenManagerImpl edmAccessTokenManagerImpl;
    if (!edmAccessTokenManagerImpl.GetAccessTokenId(info.accountId, info.appId, info.appIndex, accessTokenId)) {
        EDMLOGE("PermissionManagedStateSerializer GetAccessTokenId failed.");
        return false;
    }
    info.tokenId = static_cast<int32_t>(accessTokenId);
    for (std::string permissionName : info.permissionNames) {
        std::stringstream appPermissionKey;
        info.permissionName = permissionName;
        appPermissionKey << info.tokenId <<"\t"<< info.permissionName;
        std::string appPermissionKeyStr = appPermissionKey.str();
        result.insert(std::make_pair(appPermissionKeyStr, info));
    }
    return true;
}

bool PermissionManagedStateSerializer::WritePolicy(MessageParcel &reply,
    std::map<std::string, PermissionManagedStateInfo> &result)
{
    return true;
}

bool PermissionManagedStateSerializer::MergePolicy(std::vector<std::map<std::string,
    PermissionManagedStateInfo>> &data,
    std::map<std::string, PermissionManagedStateInfo> &result)
{
    for (auto policyMap : data) {
        for (auto iter : policyMap) {
            result.insert(std::make_pair(iter.first.c_str(), iter.second));
        }
    }
    return true;
}
} // namespace EDM
} // namespace OHOS