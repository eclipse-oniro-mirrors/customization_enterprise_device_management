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

#include "domain_call_policy_plugin.h"

#include <unordered_set>
#include <algorithm>
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "domain_call_policy_serializer.h"
#include "iplugin_manager.h"
#include "policy_flag.h"
#include "func_code_utils.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DomainCallPolicyPlugin>());

DomainCallPolicyPlugin::DomainCallPolicyPlugin()
{
    policyCode_ = EdmInterfaceCode::DOMAIN_CALL_POLICY;
    policyName_ = PolicyName::POLICY_DOMAIN_CALL_POLICY;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode DomainCallPolicyPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("DomainCallPolicyPlugin OnHandlePolicy.");
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    const std::string callType = data.ReadString();
    const int32_t flag = data.ReadInt32();
    const int32_t size = data.ReadInt32();
    std::vector<std::string> addList;
    for(int32_t i = 0; i < size; i++) {
        const std::string number = data.ReadString();
        addList.push_back(number);
    }
    auto serializer = DomainCallPolicySerializer::GetInstance();
    std::map<std::string, std::vector<std::string>> policies;
    std::map<std::string, std::vector<std::string>> mergePolicies;
    if (!serializer->Deserialize(policyData.policyData, policies) ||
        !serializer->Deserialize(policyData.mergePolicyData, mergePolicies)) {
        EDMLOGE("OnHandlePolicy Deserialize current policy and merge policy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string policyTye;
    if (callType == EdmConstants::CallPolicy::OUTGOING && flag == (int32_t)PolicyFlag::BLOCK_LIST) {
        policyTye = EdmConstants::CallPolicy::BLOCK_OUTGOING;
    } else if (callType == EdmConstants::CallPolicy::OUTGOING && flag == (int32_t)PolicyFlag::TRUST_LIST) {
        policyTye = EdmConstants::CallPolicy::TRUST_OUTGOING;
    } else if (callType == EdmConstants::CallPolicy::INCOMING && flag == (int32_t)PolicyFlag::BLOCK_LIST) {
        policyTye = EdmConstants::CallPolicy::BLOCK_INCOMING;
    } else if (callType == EdmConstants::CallPolicy::INCOMING && flag == (int32_t)PolicyFlag::TRUST_LIST) {
        policyTye = EdmConstants::CallPolicy::TRUST_INCOMING;
    } else {
        return EdmReturnErrCode::PARAM_ERROR;
    }
    if (type == FuncOperateType::SET) {
        AddCurrentAndMergePolicy(policies, mergePolicies, policyTye, addList);
    } else if (type == FuncOperateType::REMOVE) {
        RemoveCurrentAndMergePolicy(policies, mergePolicies, policyTye, addList);
    } else {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    std::string afterHandle;
    std::string afterMerge;
    if (!serializer->Serialize(policies, afterHandle) || !serializer->Serialize(mergePolicies, afterMerge)) {
        EDMLOGE("DomainCallPolicyPlugin::OnHandlePolicy Serialize current policy and merge policy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    EDMLOGI("DomainCallPolicyPlugin OnHandlePolicy afterHandle: %{public}s.", afterHandle.c_str());
    policyData.isChanged = true;
    policyData.policyData = afterHandle;
    policyData.mergePolicyData = afterMerge;

    return ERR_OK;
}

ErrCode DomainCallPolicyPlugin::AddCurrentAndMergePolicy(
    std::map<std::string, std::vector<std::string>> &policies,
    std::map<std::string, std::vector<std::string>> &mergePolicies, const std::string &policyTye,
    const std::vector<std::string> &addList)
{
    EDMLOGI("DomainCallPolicyPlugin AddCurrentAndMergePolicy.");
    // 合并去重
    std::vector<std::string> &numberList = policies[policyTye];
    std::unordered_set<std::string> uset;
    uset.insert(numberList.begin(), numberList.end());
    uset.insert(addList.begin(), addList.end());
    std::vector<std::string> result(uset.begin(), uset.end());
    
    policies[policyTye] = result;

    for (auto policy : policies) {
        if (mergePolicies.find(policy.first) == mergePolicies.end()) {
            mergePolicies[policy.first] = policy.second;
            continue;
        }
        mergePolicies[policy.first].insert(mergePolicies[policy.first].end(),
            policy.second.begin(), policy.second.end());
    }
    return ERR_OK;
}

ErrCode DomainCallPolicyPlugin::RemoveCurrentAndMergePolicy(
    std::map<std::string, std::vector<std::string>> &policies,
    std::map<std::string, std::vector<std::string>> &mergePolicies, const std::string &policyTye,
    const std::vector<std::string> &addList)
{
    std::vector<std::string> numberList = policies[policyTye];

    for (auto it = addList.begin(); it != addList.end(); ++it) {
        numberList.erase(std::remove(numberList.begin(), numberList.end(), *it), numberList.end());
    }
    policies[policyTye] = numberList;

    for (auto policy : policies) {
        if (mergePolicies.find(policy.first) == mergePolicies.end()) {
            mergePolicies[policy.first] = policy.second;
            continue;
        }
        mergePolicies[policy.first].insert(mergePolicies[policy.first].end(),
            policy.second.begin(), policy.second.end());
    }
    return ERR_OK;
}

ErrCode DomainCallPolicyPlugin::GetOthersMergePolicyData(const std::string &adminName,
    std::string &othersMergePolicyData)
{
    AdminValueItemsMap adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues);
    EDMLOGD("IPluginTemplate::GetOthersMergePolicyData %{public}s value size %{public}d.", GetPolicyName().c_str(),
        (uint32_t)adminValues.size());
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
    std::map<std::string, std::vector<std::string>> mergeData;
    auto serializer = DomainCallPolicySerializer::GetInstance();
    for (const auto &item : adminValues) {
        std::map<std::string, std::vector<std::string>> dataItem;
        if (item.second.empty()) {
            continue;
        }
        if (!serializer->Deserialize(item.second, dataItem)) {
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
        for (auto item : dataItem) {
            if (mergeData.find(item.first) == mergeData.end()) {
                mergeData[item.first] = item.second;
                continue;
            }
            mergeData[item.first].insert(mergeData[item.first].end(),
                item.second.begin(), item.second.end());
        }
    }

    if (!serializer->Serialize(mergeData, othersMergePolicyData)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode DomainCallPolicyPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    const std::string callType = data.ReadString();
    const int32_t flag = data.ReadInt32();
    EDMLOGI("DomainCallPolicyPlugin::OnGetPolicy callType:%{public}s, flag:%{public}d", callType.c_str(), flag);
    std::string policyTye;
    if (callType == EdmConstants::CallPolicy::OUTGOING && flag == (int32_t)PolicyFlag::BLOCK_LIST) {
        policyTye = EdmConstants::CallPolicy::BLOCK_OUTGOING;
    } else if (callType == EdmConstants::CallPolicy::OUTGOING && flag == (int32_t)PolicyFlag::TRUST_LIST) {
        policyTye = EdmConstants::CallPolicy::TRUST_OUTGOING;
    } else if (callType == EdmConstants::CallPolicy::INCOMING && flag == (int32_t)PolicyFlag::BLOCK_LIST) {
        policyTye = EdmConstants::CallPolicy::BLOCK_INCOMING;
    } else if (callType == EdmConstants::CallPolicy::INCOMING && flag == (int32_t)PolicyFlag::TRUST_LIST) {
        policyTye = EdmConstants::CallPolicy::TRUST_INCOMING;
    } else {
        return EdmReturnErrCode::PARAM_ERROR;
    }

    auto serializer = DomainCallPolicySerializer::GetInstance();
    std::map<std::string, std::vector<std::string>> policies;
    if (!serializer->Deserialize(policyData, policies)) {
        EDMLOGE("DomainCallPolicyPlugin::OnGetPolicy Deserialize fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    int32_t size = 0;
    auto it = policies.find(policyTye);
    if (it == policies.end()) {
        reply.WriteInt32(size);
    } else {
        reply.WriteInt32(it->second.size());
        for (const auto &number : it->second) {
            reply.WriteString(number);
        }
    }
    return ERR_OK;
}

ErrCode DomainCallPolicyPlugin::OnAdminRemove(const std::string &adminName,
    const std::string &policyData, const std::string &mergeData, int32_t userId)
{
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
