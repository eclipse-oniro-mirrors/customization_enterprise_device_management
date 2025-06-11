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
#include "parameters.h"
#include "policy_flag.h"
#include "func_code_utils.h"
#include "call_manager_client.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DomainCallPolicyPlugin>());
const std::string PARAM_DISALLOWED_TELEPHONY_CALL = "persist.edm.telephony_call_disable";

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
    if (system::GetBoolParameter(PARAM_DISALLOWED_TELEPHONY_CALL, false)) {
        EDMLOGE("DomainCallPolicyPlugin::OnHandlePolicy failed, because telephony call disallow");
        return EdmReturnErrCode::ENTERPRISE_POLICES_DENIED;
    }
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    const std::string callType = data.ReadString();
    const int32_t flag = data.ReadInt32();
    std::vector<std::string> addList;
    data.ReadStringVector(&addList);
    auto serializer = DomainCallPolicySerializer::GetInstance();
    std::map<std::string, DomainCallPolicyType> policies;
    std::map<std::string, DomainCallPolicyType> mergePolicies;
    if (!serializer->Deserialize(policyData.policyData, policies) ||
        !serializer->Deserialize(policyData.mergePolicyData, mergePolicies)) {
        EDMLOGE("OnHandlePolicy Deserialize current policy and merge policy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode ret = ERR_OK;
    if (type == FuncOperateType::SET) {
        ret = AddCurrentAndMergePolicy(policies, mergePolicies, callType, flag, addList);
    } else if (type == FuncOperateType::REMOVE) {
        ret = RemoveCurrentAndMergePolicy(policies, mergePolicies, callType, flag, addList);
    } else {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (ret != ERR_OK) {
        return ret;
    }
    std::string afterHandle;
    std::string afterMerge;
    if (!serializer->Serialize(policies, afterHandle) || !serializer->Serialize(mergePolicies, afterMerge)) {
        EDMLOGE("DomainCallPolicyPlugin::OnHandlePolicy Serialize current policy and merge policy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    policyData.isChanged = true;
    policyData.policyData = afterHandle;
    policyData.mergePolicyData = afterMerge;
    DelayedSingleton<Telephony::CallManagerClient>::GetInstance()->Init(TELEPHONY_CALL_MANAGER_SYS_ABILITY_ID);
    DelayedSingleton<Telephony::CallManagerClient>::GetInstance()->SetCallPolicyInfo(
        mergePolicies[EdmConstants::CallPolicy::OUTGOING].policyFlag,
        mergePolicies[EdmConstants::CallPolicy::OUTGOING].numberList,
        mergePolicies[EdmConstants::CallPolicy::INCOMING].policyFlag,
        mergePolicies[EdmConstants::CallPolicy::INCOMING].numberList);

    return ERR_OK;
}

ErrCode DomainCallPolicyPlugin::AddCurrentAndMergePolicy(
    std::map<std::string, DomainCallPolicyType> &policies,
    std::map<std::string, DomainCallPolicyType> &mergePolicies, const std::string &policyTye,
    const int32_t flag, const std::vector<std::string> &addList)
{
    EDMLOGI("DomainCallPolicyPlugin AddCurrentAndMergePolicy.");
    // 黑/白名单 互斥
    std::vector<std::string> &numberList = policies[policyTye].numberList;
    int32_t policyFlag = mergePolicies[policyTye].policyFlag;
    if (flag != policyFlag && numberList.size() > 0) {
        EDMLOGE("DomainCallPolicyPlugin::AddCurrentAndMergePolicy current policy is "
            "%{public}d, set value is %{public}d", policyFlag, flag);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    // 合并去重
    std::unordered_set<std::string> uset;
    uset.insert(numberList.begin(), numberList.end());
    uset.insert(addList.begin(), addList.end());
    std::vector<std::string> result(uset.begin(), uset.end());
    policies[policyTye].numberList = result;
    policies[policyTye].policyFlag = flag;

    for (auto policy : policies) {
        if (mergePolicies.find(policy.first) == mergePolicies.end()) {
            mergePolicies[policy.first] = policy.second;
            continue;
        }
        uset.clear();
        uset.insert(mergePolicies[policy.first].numberList.begin(), mergePolicies[policy.first].numberList.end());
        uset.insert(policy.second.numberList.begin(), policy.second.numberList.end());
        std::vector<std::string> mergeResult(uset.begin(), uset.end());
        mergePolicies[policy.first].numberList = mergeResult;
        mergePolicies[policy.first].policyFlag = policy.second.policyFlag;
    }
    return ERR_OK;
}

ErrCode DomainCallPolicyPlugin::RemoveCurrentAndMergePolicy(
    std::map<std::string, DomainCallPolicyType> &policies,
    std::map<std::string, DomainCallPolicyType> &mergePolicies, const std::string &policyTye,
    const int32_t flag, const std::vector<std::string> &addList)
{
    std::vector<std::string> numberList = policies[policyTye].numberList;
    int32_t policyFlag = mergePolicies[policyTye].policyFlag;
    if (flag != policyFlag && numberList.size() > 0) {
        EDMLOGE("DomainCallPolicyPlugin::AddCurrentAndMergePolicy current policy is "
            "%{public}d, set value is %{public}d", policyFlag, flag);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    for (auto it = addList.begin(); it != addList.end(); ++it) {
        numberList.erase(std::remove(numberList.begin(), numberList.end(), *it), numberList.end());
    }
    policies[policyTye].numberList = numberList;

    for (auto policy : policies) {
        if (mergePolicies.find(policy.first) == mergePolicies.end()) {
            mergePolicies[policy.first] = policy.second;
            continue;
        }
        std::unordered_set<std::string> uset;
        uset.insert(mergePolicies[policy.first].numberList.begin(), mergePolicies[policy.first].numberList.end());
        uset.insert(policy.second.numberList.begin(), policy.second.numberList.end());
        std::vector<std::string> mergeResult(uset.begin(), uset.end());
        mergePolicies[policy.first].numberList = mergeResult;
        mergePolicies[policy.first].policyFlag = policy.second.policyFlag;
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
    std::map<std::string, DomainCallPolicyType> mergeData;
    auto serializer = DomainCallPolicySerializer::GetInstance();
    for (const auto &item : adminValues) {
        std::map<std::string, DomainCallPolicyType> dataItem;
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
            mergeData[item.first].numberList.insert(mergeData[item.first].numberList.end(),
                item.second.numberList.begin(), item.second.numberList.end());
            mergeData[item.first].policyFlag = item.second.policyFlag;
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
    
    auto serializer = DomainCallPolicySerializer::GetInstance();
    std::map<std::string, DomainCallPolicyType> policies;
    if (!serializer->Deserialize(policyData, policies)) {
        EDMLOGE("DomainCallPolicyPlugin::OnGetPolicy Deserialize fail");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    reply.WriteInt32(ERR_OK);
    int32_t size = 0;
    auto it = policies.find(callType);
    if (it == policies.end()) {
        reply.WriteInt32(size);
    } else {
        if (flag == it->second.policyFlag) {
            data.WriteStringVector(it->second.numberList);
        } else {
            reply.WriteInt32(size);
        }
    }
    return ERR_OK;
}

ErrCode DomainCallPolicyPlugin::OnAdminRemove(const std::string &adminName,
    const std::string &policyData, const std::string &mergeData, int32_t userId)
{
    auto serializer = DomainCallPolicySerializer::GetInstance();
    std::map<std::string, DomainCallPolicyType> policies;
    std::map<std::string, DomainCallPolicyType> mergePolicies;
    if (!serializer->Deserialize(policyData, policies) ||
        !serializer->Deserialize(mergeData, mergePolicies)) {
        EDMLOGE("OnHandlePolicy Deserialize current policy and merge policy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    DelayedSingleton<Telephony::CallManagerClient>::GetInstance()->SetCallPolicyInfo(
        mergePolicies[EdmConstants::CallPolicy::OUTGOING].policyFlag,
        mergePolicies[EdmConstants::CallPolicy::OUTGOING].numberList,
        mergePolicies[EdmConstants::CallPolicy::INCOMING].policyFlag,
        mergePolicies[EdmConstants::CallPolicy::INCOMING].numberList);
    return ERR_OK;
    return ERR_OK;
}

void DomainCallPolicyPlugin::OnOtherServiceStart(int32_t systemAbilityId)
{
    EDMLOGI("DomainCallPolicyPlugin::OnOtherServiceStart systemAbilityId:%{public}d", systemAbilityId);
    std::string policyData;
    IPolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_DOMAIN_CALL_POLICY,
        policyData, EdmConstants::DEFAULT_USER_ID);
    auto serializer_ = DomainCallPolicySerializer::GetInstance();
    std::map<std::string, DomainCallPolicyType> policies;
    serializer_->Deserialize(policyData, policies);
    if (policies.size() > 0) {
        DelayedSingleton<Telephony::CallManagerClient>::GetInstance()->Init(TELEPHONY_CALL_MANAGER_SYS_ABILITY_ID);
        DelayedSingleton<Telephony::CallManagerClient>::GetInstance()->SetCallPolicyInfo(
            policies[EdmConstants::CallPolicy::OUTGOING].policyFlag,
            policies[EdmConstants::CallPolicy::OUTGOING].numberList,
            policies[EdmConstants::CallPolicy::INCOMING].policyFlag,
            policies[EdmConstants::CallPolicy::INCOMING].numberList);
    }
}
} // namespace EDM
} // namespace OHOS
