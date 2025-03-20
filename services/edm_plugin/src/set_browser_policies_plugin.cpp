/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "set_browser_policies_plugin.h"

#include "bundle_manager_utils.h"
#include "cjson_check.h"
#include "cjson_serializer.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "edm_ipc_interface_code.h"
#include "map_string_serializer.h"
#include "want.h"
#include "iplugin_manager.h"

static constexpr int32_t SET_POLICY_PARAM_NUM = 3;
static constexpr int32_t SET_POLICY_APPID_INDEX = 0;
static constexpr int32_t SET_POLICY_POLICY_NAME_INDEX = 1;
static constexpr int32_t SET_POLICY_POLICY_VALUE_INDEX = 2;

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<SetBrowserPoliciesPlugin>());
const char* const BROWSER_POLICY_CHANGED_EVENT = "com.ohos.edm.browserpolicychanged";
const char* const EMPTY_OBJECT_STRING = "{}";

SetBrowserPoliciesPlugin::SetBrowserPoliciesPlugin()
{
    policyCode_ = EdmInterfaceCode::SET_BROWSER_POLICIES;
    policyName_ = PolicyName::POLICY_SET_BROWSER_POLICIES;
    permissionMap_.insert(std::make_pair(
        FuncOperateType::SET, IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_SET_BROWSER_POLICY,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC)));
    permissionMap_.insert(std::make_pair(
        FuncOperateType::GET, IPlugin::PolicyPermissionConfig("", IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC)));
    needSave_ = true;
}

ErrCode SetBrowserPoliciesPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGD("SetBrowserPoliciesPlugin OnHandlePolicy.");
    std::vector<std::string> params;
    data.ReadStringVector(&params);
    if (params.size() < SET_POLICY_PARAM_NUM) {
        EDMLOGD("SetBrowserPolicyPlugin param invalid.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    std::string appid = params[SET_POLICY_APPID_INDEX];
    std::string policyName = params[SET_POLICY_POLICY_NAME_INDEX];
    std::string policyValue = params[SET_POLICY_POLICY_VALUE_INDEX];
    if (appid.empty()) {
        EDMLOGD("SetBrowserPolicyPlugin param invalid.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (policyData.policyData.empty()) {
        policyData.policyData = EMPTY_OBJECT_STRING;
    }
    if (policyData.mergePolicyData.empty()) {
        policyData.mergePolicyData = EMPTY_OBJECT_STRING;
    }

    auto serializer = CjsonSerializer::GetInstance();
    cJSON* currentPolicies = nullptr;
    if (!serializer->Deserialize(policyData.policyData, currentPolicies)) {
        EDMLOGE("SetBrowserPolicyPlugin parse current policies error!");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    cJSON* mergePolicies = nullptr;
    if (!serializer->Deserialize(policyData.mergePolicyData, mergePolicies)) {
        EDMLOGE("SetBrowserPolicyPlugin parse merge policies error!");
        cJSON_Delete(currentPolicies);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    ErrCode errCode = ERR_OK;
    if (policyName.empty()) {
        errCode = SetRootPolicy(currentPolicies, mergePolicies, appid, policyValue);
    } else {
        errCode = SetPolicy(currentPolicies, mergePolicies, appid, policyName, policyValue);
    }
    if (errCode != ERR_OK) {
        cJSON_Delete(currentPolicies);
        cJSON_Delete(mergePolicies);
        return errCode;
    }
    ErrCode ret = UpdateCurrentAndMergePolicy(currentPolicies, mergePolicies, policyData);
    cJSON_Delete(currentPolicies);
    cJSON_Delete(mergePolicies);
    return ret;
}

ErrCode SetBrowserPoliciesPlugin::UpdateCurrentAndMergePolicy(cJSON* currentPolicies, cJSON* mergePolicies,
    HandlePolicyData &policyData)
{
    cJSON* currentItem;
    cJSON_ArrayForEach(currentItem, currentPolicies) {
        cJSON* policies = cJSON_Duplicate(currentItem, true);
        if (!cJSON_HasObjectItem(mergePolicies, currentItem->string)) {
            if (!cJSON_AddItemToObject(mergePolicies, currentItem->string, policies)) {
                cJSON_Delete(policies);
            }
            continue;
        }
        cJSON* policyItem;
        cJSON_ArrayForEach(policyItem, policies) {
            cJSON* policy = cJSON_Duplicate(policyItem, true);
            if (!cJSON_AddItemToObject(mergePolicies->child, policyItem->string, policy)) {
                cJSON_Delete(policy);
            }
        }
    }

    auto serializer = CjsonSerializer::GetInstance();
    std::string afterHandle;
    std::string afterMerge;
    if (!serializer->Serialize(currentPolicies, afterHandle) || !serializer->Serialize(mergePolicies, afterMerge)) {
        EDMLOGE("SetBrowserPoliciesPlugin serialize current policy and merge policy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    policyData.isChanged = afterHandle != policyData.policyData;
    if (policyData.isChanged) {
        policyData.policyData = afterHandle;
    }
    policyData.mergePolicyData = afterMerge;
    return ERR_OK;
}

ErrCode SetBrowserPoliciesPlugin::SetRootPolicy(cJSON* currentPolicies, cJSON* mergePolicies, const std::string &appid,
    const std::string &policyValue)
{
    cJSON* policy = cJSON_GetObjectItem(mergePolicies, appid.c_str());
    if (policy != nullptr) {
        EDMLOGE("SetBrowserPolicyPlugin another admin has already set this browser policy for this application.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    cJSON_DeleteItemFromObject(currentPolicies, appid.c_str());
    if (!policyValue.empty()) {
        cJSON* value = nullptr;
        if (!CjsonSerializer::GetInstance()->Deserialize(policyValue, value)) {
            EDMLOGE("SetBrowserPolicyPlugin parse policyValue error!");
            return EdmReturnErrCode::PARAM_ERROR;
        }
        if (!cJSON_AddItemToObject(currentPolicies, appid.c_str(), value)) {
            EDMLOGE("SetBrowserPolicyPlugin SetRootPolicy AddItemToObject error!");
            cJSON_Delete(value);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

ErrCode SetBrowserPoliciesPlugin::SetPolicy(cJSON* currentPolicies, cJSON* mergePolicies, const std::string &appid,
    const std::string &policyName, const std::string &policyValue)
{
    cJSON* mergePolicy = cJSON_GetObjectItem(mergePolicies, appid.c_str());
    if (mergePolicy != nullptr) {
        if (cJSON_GetObjectItem(mergePolicy, policyName.c_str()) != nullptr) {
            EDMLOGE("SetBrowserPoliciesPlugin another admin has already set this item policy for this application.");
            return EdmReturnErrCode::PARAM_ERROR;
        }
    }
    cJSON* policy = cJSON_GetObjectItem(currentPolicies, appid.c_str());
    if (policy == nullptr) {
        CJSON_CREATE_OBJECT_AND_CHECK(policy, EdmReturnErrCode::SYSTEM_ABNORMALLY);
        if (!cJSON_AddItemToObject(currentPolicies, appid.c_str(), policy)) {
            EDMLOGE("SetBrowserPolicyPlugin AddItemToObject appid error!");
            cJSON_Delete(policy);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    cJSON_DeleteItemFromObject(policy, policyName.c_str());
    return SetPolicyValue(policy, policyName, policyValue);
}

ErrCode SetBrowserPoliciesPlugin::SetPolicyValue(cJSON* policy, std::string policyName,
    std::string policyValue)
{
    if (!policyValue.empty()) {
        cJSON* value = nullptr;
        if (!CjsonSerializer::GetInstance()->Deserialize(policyValue, value)) {
            EDMLOGE("SetBrowserPolicyPlugin parse policyValue error!");
            return EdmReturnErrCode::PARAM_ERROR;
        }
        if (!cJSON_AddItemToObject(policy, policyName.c_str(), value)) {
            EDMLOGE("SetBrowserPolicyPlugin AddItemToObject value error!");
            cJSON_Delete(value);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

void SetBrowserPoliciesPlugin::OnHandlePolicyDone(std::uint32_t funcCode, const std::string &adminName,
    bool isGlobalChanged, int32_t userId)
{
    if (!isGlobalChanged) {
        return;
    }
    NotifyBrowserPolicyChanged();
}

ErrCode SetBrowserPoliciesPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    return ERR_OK;
}

void SetBrowserPoliciesPlugin::NotifyBrowserPolicyChanged()
{
    EDMLOGD("SetBrowserPoliciesPlugin NotifyBrowserPolicyChanged.");
    AAFwk::Want want;
    want.SetAction(BROWSER_POLICY_CHANGED_EVENT);
    EventFwk::CommonEventData eventData;
    eventData.SetWant(want);
    if (!EventFwk::CommonEventManager::PublishCommonEvent(eventData)) {
        EDMLOGE("NotifyBrowserPolicyChanged failed.");
    }
}

ErrCode SetBrowserPoliciesPlugin::GetOthersMergePolicyData(const std::string &adminName,
    std::string &othersMergePolicyData)
{
    EDMLOGD("SetBrowserPoliciesPlugin GetOthersMergePolicyData before.");
    AdminValueItemsMap adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues);
    if (adminValues.empty()) {
        return ERR_OK;
    }
    auto entry = adminValues.find(adminName);
    if (entry != adminValues.end()) {
        adminValues.erase(entry);
    }
    if (adminValues.empty()) {
        return ERR_OK;
    }
    return MergeBrowserPolicy(adminValues, othersMergePolicyData);
}

ErrCode SetBrowserPoliciesPlugin::MergeBrowserPolicy(const AdminValueItemsMap &adminValues, std::string &policyData)
{
    cJSON* root = nullptr;
    CJSON_CREATE_OBJECT_AND_CHECK(root, EdmReturnErrCode::SYSTEM_ABNORMALLY);
    for (const auto &item : adminValues) {
        if (!AddBrowserPoliciesToRoot(root, item.second)) {
            EDMLOGE("SetBrowserPoliciesPlugin MergePolicyData error");
            cJSON_Delete(root);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }

    auto serializer = CjsonSerializer::GetInstance();
    serializer->Serialize(root, policyData);
    EDMLOGD("SetBrowserPoliciesPlugin MergePolicyData after: %{public}s", policyData.c_str());
    cJSON_Delete(root);
    return ERR_OK;
}

bool SetBrowserPoliciesPlugin::AddBrowserPoliciesToRoot(cJSON* root, const std::string &policiesString)
{
    if (policiesString.empty()) {
        return true;
    }
    cJSON* adminPolicies = cJSON_Parse(policiesString.c_str());
    if (adminPolicies == nullptr) {
        return false;
    }
    cJSON *adminPolicy = adminPolicies->child;
    while (adminPolicy != nullptr) {
        cJSON* policy = cJSON_GetObjectItem(root, adminPolicy->string);
        if (policy == nullptr) {
            cJSON* copy = cJSON_Duplicate(adminPolicy, true);
            if (copy == nullptr) {
                cJSON_Delete(adminPolicies);
                return false;
            }
            if (!cJSON_AddItemToObject(root, adminPolicy->string, copy)) {
                cJSON_Delete(copy);
                cJSON_Delete(adminPolicies);
                return false;
            }
            adminPolicy = adminPolicy->next;
            continue;
        }
        if (!AddBrowserPolicyToRoot(policy, adminPolicy)) {
            cJSON_Delete(adminPolicies);
            return false;
        }
        adminPolicy = adminPolicy->next;
    }
    cJSON_Delete(adminPolicies);
    return true;
}

bool SetBrowserPoliciesPlugin::AddBrowserPolicyToRoot(cJSON* policy, const cJSON* adminPolicy)
{
    cJSON *item = adminPolicy->child;
    while (item != nullptr) {
        cJSON_DeleteItemFromObject(policy, item->string);
        cJSON* copy = cJSON_Duplicate(item, true);
        if (copy == nullptr) {
            return false;
        }
        if (!cJSON_AddItemToObject(policy, item->string, copy)) {
            cJSON_Delete(copy);
            return false;
        }
        item = item->next;
    }
    return true;
}
} // namespace EDM
} // namespace OHOS
