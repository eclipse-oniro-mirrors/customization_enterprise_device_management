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
#include "cjson_serializer.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "map_string_serializer.h"
#include "want.h"
#include "plugin_manager.h"

static constexpr int32_t SET_POLICY_PARAM_NUM = 3;
static constexpr int32_t SET_POLICY_APPID_INDEX = 0;
static constexpr int32_t SET_POLICY_POLICY_NAME_INDEX = 1;
static constexpr int32_t SET_POLICY_POLICY_VALUE_INDEX = 2;

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(std::make_shared<SetBrowserPoliciesPlugin>());
const char* const BROWSER_POLICY_CHANGED_EVENT = "com.ohos.edm.browserpolicychanged";

SetBrowserPoliciesPlugin::SetBrowserPoliciesPlugin()
{
    policyCode_ = EdmInterfaceCode::SET_BROWSER_POLICIES;
    policyName_ = "set_browser_policies";
    permissionMap_.insert(std::make_pair(
        FuncOperateType::SET, IPlugin::PolicyPermissionConfig("ohos.permission.ENTERPRISE_SET_BROWSER_POLICY",
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC)));
    needSave_ = true;
}

ErrCode SetBrowserPoliciesPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGD("SetBrowserPoliciesPlugin OnHandlePolicy.");
    std::string beforeHandle = policyData.policyData;
    std::string afterHandle;
    ErrCode errCode = ERR_OK;
    int32_t type = data.ReadInt32();
    if (type == EdmConstants::SET_POLICY_TYPE) {
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
            beforeHandle = "{}";
        }

        if (policyName.empty()) {
            errCode = SetRootPolicy(beforeHandle, appid, policyValue, afterHandle);
        } else {
            errCode = SetPolicy(beforeHandle, appid, policyName, policyValue, afterHandle);
        }
    } else if (type == EdmConstants::SET_POLICIES_TYPE) {
        auto serializer_ = MapStringSerializer::GetInstance();
        std::map<std::string, std::string> policies;
        std::map<std::string, std::string> policyDataMap;
        serializer_->GetPolicy(data, policies);
        serializer_->Deserialize(beforeHandle, policyDataMap);
        errCode = SetPolicies(policies, policyDataMap);
        serializer_->Serialize(policyDataMap, afterHandle);
    } else {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
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

ErrCode SetBrowserPoliciesPlugin::SetPolicies(std::map<std::string, std::string> &policies,
    std::map<std::string, std::string> &currentData)
{
    EDMLOGD("SetBrowserPoliciesPlugin OnSetPolicy.");
    if (policies.empty()) {
        EDMLOGD("SetBrowserPoliciesPlugin policies is empty.");
        return EdmReturnErrCode::PARAM_ERROR;
    }
    auto iter = policies.begin();
    if (iter->second.empty()) {
        currentData.erase(iter->first);
    } else {
        currentData[iter->first] = iter->second;
    }
    return ERR_OK;
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
            EDMLOGD("SetBrowserPolicyPlugin parse policyValue error!");
            cJSON_Delete(policies);
            return EdmReturnErrCode::PARAM_ERROR;
        }
        std::string valueString;
        serializer_->Serialize(value, valueString);
        cJSON_Delete(value);
        cJSON_AddStringToObject(policies, appid.c_str(), valueString.c_str());
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
        EDMLOGD("SetBrowserPolicyPlugin parse policies error!");
        return EdmReturnErrCode::PARAM_ERROR;
    }

    cJSON* beforeParsedPolicy = cJSON_GetObjectItem(policies, appid.c_str());
    cJSON* policy;
    if (beforeParsedPolicy == nullptr) {
        cJSON_AddItemToObject(policies, appid.c_str(), cJSON_CreateObject());
        policy = cJSON_CreateObject();
    } else {
        std::string beforeParsedPolicyString = cJSON_GetStringValue(beforeParsedPolicy);
        if (!serializer_->Deserialize(beforeParsedPolicyString, policy)) {
            EDMLOGD("SetBrowserPolicyPlugin parse policies error!");
            cJSON_Delete(policies);
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    cJSON_DeleteItemFromObject(policy, policyName.c_str());
    if (!policyValue.empty()) {
        cJSON* value = nullptr;
        if (!serializer_->Deserialize(policyValue, value)) {
            EDMLOGD("SetBrowserPolicyPlugin parse policyValue error!");
            cJSON_Delete(policies);
            cJSON_Delete(policy);
            return EdmReturnErrCode::PARAM_ERROR;
        }
        cJSON_AddItemToObject(policy, policyName.c_str(), value);
    }
    std::string policyString;
    serializer_->Serialize(policy, policyString);
    cJSON_ReplaceItemInObject(policies, appid.c_str(), cJSON_CreateString(policyString.c_str()));
    serializer_->Serialize(policies, afterHandle);
    cJSON_Delete(policies);
    cJSON_Delete(policy);
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
    auto mapStringSerilizer_ = MapStringSerializer::GetInstance();
    std::map<std::string, std::string> policies;
    mapStringSerilizer_->Deserialize(policyData, policies);
    std::string appId = data.ReadString();
    if (appId.empty() && FAILED(BundleManagerUtils::GetAppIdByCallingUid(appId))) {
        reply.WriteInt32(EdmReturnErrCode::SYSTEM_ABNORMALLY);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    std::string policy;
    if (policies.count(appId) > 0) {
        policy = policies[appId];
    }
    reply.WriteString(policy);
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
} // namespace EDM
} // namespace OHOS
