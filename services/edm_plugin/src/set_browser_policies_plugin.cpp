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
#include "edm_constants.h"
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
    policyName_ = "set_browser_policies";
    permissionMap_.insert(std::make_pair(
        FuncOperateType::SET, IPlugin::PolicyPermissionConfig("ohos.permission.ENTERPRISE_SET_BROWSER_POLICY",
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
    std::string beforeHandle = policyData.policyData;
    std::string afterHandle;
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

    if (beforeHandle.empty()) {
        beforeHandle = EMPTY_OBJECT_STRING;
    }

    ErrCode errCode = ERR_OK;
    if (policyName.empty()) {
        errCode = SetRootPolicy(beforeHandle, appid, policyValue, afterHandle);
    } else {
        errCode = SetPolicy(beforeHandle, appid, policyName, policyValue, afterHandle);
    }

    if (errCode != ERR_OK) {
        return errCode;
    }
    
    policyData.isChanged = afterHandle != beforeHandle;
    if (policyData.isChanged) {
        policyData.policyData = afterHandle;
    }

    return errCode;
}

ErrCode SetBrowserPoliciesPlugin::SetRootPolicy(const std::string policyData, std::string appid,
    std::string policyValue, std::string &afterHandle)
{
    cJSON* policies = nullptr;
    auto serializer_ = CjsonSerializer::GetInstance();
    if (!serializer_->Deserialize(policyData, policies)) {
        EDMLOGD("SetBrowserPolicyPlugin parse policies error!");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    cJSON_DeleteItemFromObject(policies, appid.c_str());
    if (!policyValue.empty()) {
        cJSON* value = nullptr;
        if (!serializer_->Deserialize(policyValue, value)) {
            EDMLOGE("SetBrowserPolicyPlugin parse policyValue error!");
            cJSON_Delete(policies);
            return EdmReturnErrCode::PARAM_ERROR;
        }
        if (!cJSON_AddItemToObject(policies, appid.c_str(), value)) {
            EDMLOGE("SetBrowserPolicyPlugin SetRootPolicy AddItemToObject error!");
            cJSON_Delete(policies);
            cJSON_Delete(value);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    serializer_->Serialize(policies, afterHandle);
    cJSON_Delete(policies);
    return ERR_OK;
}

ErrCode SetBrowserPoliciesPlugin::SetPolicy(const std::string policyData, std::string appid, std::string policyName,
    std::string policyValue, std::string &afterHandle)
{
    cJSON* policies = nullptr;
    auto serializer_ = CjsonSerializer::GetInstance();
    if (!serializer_->Deserialize(policyData, policies)) {
        EDMLOGE("SetBrowserPolicyPlugin parse policies error!");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    cJSON* policy = cJSON_GetObjectItem(policies, appid.c_str());
    if (policy == nullptr) {
        CJSON_CREATE_OBJECT_AND_CHECK_AND_CLEAR(policy, EdmReturnErrCode::SYSTEM_ABNORMALLY, policies);
        if (!cJSON_AddItemToObject(policies, appid.c_str(), policy)) {
            EDMLOGE("SetBrowserPolicyPlugin AddItemToObject appid error!");
            cJSON_Delete(policies);
            cJSON_Delete(policy);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    cJSON_DeleteItemFromObject(policy, policyName.c_str());
    ErrCode ret = SetPolicyValue(policy, policyName, policyValue);
    if (ret != ERR_OK) {
        cJSON_Delete(policies);
        return ret;
    }
    serializer_->Serialize(policies, afterHandle);
    cJSON_Delete(policies);
    return ERR_OK;
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
    std::string appId = data.ReadString();
    if (appId.empty() && FAILED(BundleManagerUtils::GetAppIdByCallingUid(appId))) {
        reply.WriteInt32(EdmReturnErrCode::PARAM_ERROR);
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (policyData.empty()) {
        policyData = EMPTY_OBJECT_STRING;
    }
    cJSON* policies = nullptr;
    auto serializer = CjsonSerializer::GetInstance();
    if (!serializer->Deserialize(policyData, policies)) {
        EDMLOGE("SetBrowserPolicyPlugin OnGetPolicy Deserialize error!");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string retString;
    cJSON* policy = cJSON_GetObjectItem(policies, appId.c_str());
    if (policy != nullptr) {
        serializer->Serialize(policy, retString);
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteString(retString);
    cJSON_Delete(policies);
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

ErrCode SetBrowserPoliciesPlugin::MergePolicyData(const std::string &adminName, std::string &policyData)
{
    EDMLOGD("SetBrowserPoliciesPlugin MergePolicyData before: %{public}s", policyData.c_str());
    AdminValueItemsMap adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues);
    if (adminValues.empty()) {
        return ERR_OK;
    }
    auto entry = adminValues.find(adminName);
    if (entry != adminValues.end()) {
        adminValues.erase(entry);
    }
    if (adminValues.empty() && policyData.empty()) {
        return ERR_OK;
    }
    if (!policyData.empty()) {
        adminValues[adminName] = policyData;
    }
    return MergeBrowserPolicy(adminValues, policyData);
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
