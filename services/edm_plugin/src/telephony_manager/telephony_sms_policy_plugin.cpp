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

#include "telephony_sms_policy_plugin.h"

#include <unordered_set>
#include <algorithm>
#include <cstdlib>
#include "ashmem.h"
#include "securec.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "telephony_sms_policy_serializer.h"
#include "iplugin_manager.h"
#include "parameters.h"
#include "policy_flag.h"
#include "func_code_utils.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<TelephonySmsPolicyPlugin>());
const std::string PARAM_DISALLOWED_SMS = "persist.edm.sms_disable";

namespace {
ErrCode ReadSmsNumberListFromAshmem(MessageParcel &data, std::vector<std::string> &addList)
{
    int32_t dataSize = data.ReadInt32();
    if (dataSize <= 0 || static_cast<size_t>(dataSize) > EdmConstants::MAX_PARCEL_CAPACITY_OF_ASHMEM) {
        EDMLOGE("ReadSmsNumberListFromAshmem: invalid dataSize %{public}d.", dataSize);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    sptr<Ashmem> ashmem = data.ReadAshmem();
    if (ashmem == nullptr) {
        EDMLOGE("ReadSmsNumberListFromAshmem: ReadAshmem failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (!ashmem->MapReadOnlyAshmem()) {
        EDMLOGE("ReadSmsNumberListFromAshmem: MapReadOnlyAshmem failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t offset = 0;
    const void *ashDataPtr = ashmem->ReadFromAshmem(dataSize, offset);
    if (ashDataPtr == nullptr) {
        EDMLOGE("ReadSmsNumberListFromAshmem: ReadFromAshmem failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    void *buffer = malloc(dataSize);
    if (buffer == nullptr) {
        EDMLOGE("ReadSmsNumberListFromAshmem: malloc buffer failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (memcpy_s(buffer, dataSize, ashDataPtr, dataSize) != EOK) {
        free(buffer);
        EDMLOGE("ReadSmsNumberListFromAshmem: memcpy_s failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    MessageParcel tempParcel;
    if (!tempParcel.ParseFrom(reinterpret_cast<uintptr_t>(buffer), dataSize)) {
        free(buffer);
        EDMLOGE("ReadSmsNumberListFromAshmem: ParseFrom failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (!tempParcel.ReadStringVector(&addList)) {
        EDMLOGE("ReadSmsNumberListFromAshmem: ReadStringVector failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace

TelephonySmsPolicyPlugin::TelephonySmsPolicyPlugin()
{
    policyCode_ = EdmInterfaceCode::TELEPHONY_SMS_POLICY;
    policyName_ = PolicyName::POLICY_TELEPHONY_SMS_POLICY;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_TELEPHONY);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode TelephonySmsPolicyPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("TelephonySmsPolicyPlugin OnHandlePolicy.");
    if (system::GetBoolParameter(PARAM_DISALLOWED_SMS, false)) {
        EDMLOGE("TelephonySmsPolicyPlugin::OnHandlePolicy failed, because sms disallow");
        return EdmReturnErrCode::ENTERPRISE_POLICES_DENIED;
    }
    uint32_t typeCode = FUNC_TO_OPERATE(funcCode);
    FuncOperateType type = FuncCodeUtils::ConvertOperateType(typeCode);
    const std::string smsType = data.ReadString();
    const int32_t flag = data.ReadInt32();
    std::vector<std::string> addList;
    ErrCode readRet = ReadSmsNumberListFromAshmem(data, addList);
    if (readRet != ERR_OK) {
        EDMLOGE("OnHandlePolicy ReadSmsNumberListFromAshmem failed.");
        return readRet;
    }
    auto serializer = TelephonySmsPolicySerializer::GetInstance();
    std::map<std::string, TelephonySmsPolicyType> policies;
    std::map<std::string, TelephonySmsPolicyType> mergePolicies;
    if (!serializer->Deserialize(policyData.policyData, policies) ||
        !serializer->Deserialize(policyData.mergePolicyData, mergePolicies)) {
        EDMLOGE("OnHandlePolicy Deserialize current policy and merge policy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode ret = ERR_OK;
    if (type == FuncOperateType::SET) {
        ret = AddCurrentAndMergePolicy(policies, mergePolicies, smsType, flag, addList);
    } else if (type == FuncOperateType::REMOVE) {
        ret = RemoveCurrentAndMergePolicy(policies, mergePolicies, smsType, flag, addList);
    } else {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (ret != ERR_OK) {
        return ret;
    }
    std::string afterHandle;
    std::string afterMerge;
    if (!serializer->Serialize(policies, afterHandle) || !serializer->Serialize(mergePolicies, afterMerge)) {
        EDMLOGE("TelephonySmsPolicyPlugin::OnHandlePolicy Serialize current policy and merge policy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    policyData.isChanged = true;
    policyData.policyData = afterHandle;
    policyData.mergePolicyData = afterMerge;

    return ERR_OK;
}

std::vector<std::string> TelephonySmsPolicyPlugin::MergeAndRemoveDuplicates(const std::vector<std::string> &v1,
    const std::vector<std::string> &v2)
{
    std::unordered_set<std::string> uset;
    uset.insert(v1.begin(), v1.end());
    uset.insert(v2.begin(), v2.end());
    std::vector<std::string> result(uset.begin(), uset.end());
    return result;
}

bool TelephonySmsPolicyPlugin::IsTrustBlockConflict(const std::string &policyType, const int32_t flag,
    std::map<std::string, TelephonySmsPolicyType> &mergePolicies)
{
    auto iter = mergePolicies.find(policyType);
    if (iter != mergePolicies.end()) {
        std::vector<std::string> numberList = mergePolicies[policyType].numberList;
        int32_t policyFlag = mergePolicies[policyType].policyFlag;
        if (flag != policyFlag && numberList.size() > 0) {
            EDMLOGE("TelephonySmsPolicyPlugin::AddCurrentAndMergePolicy current policy is "
                "%{public}d, set value is %{public}d", policyFlag, flag);
            return true;
        }
    }

    return false;
}

ErrCode TelephonySmsPolicyPlugin::AddCurrentAndMergePolicy(
    std::map<std::string, TelephonySmsPolicyType> &policies,
    std::map<std::string, TelephonySmsPolicyType> &mergePolicies, const std::string &policyType,
    const int32_t flag, const std::vector<std::string> &addList)
{
    EDMLOGI("TelephonySmsPolicyPlugin AddCurrentAndMergePolicy.");
    auto policyManager = IPolicyManager::GetInstance();
    std::string allPolicy;
    std::map<std::string, TelephonySmsPolicyType> allpolicies;
    policyManager->GetPolicy("", PolicyName::POLICY_TELEPHONY_SMS_POLICY, allPolicy);
    auto serializer = TelephonySmsPolicySerializer::GetInstance();
    if (!serializer->Deserialize(allPolicy, allpolicies)) {
        EDMLOGE("OnHandlePolicy Deserialize current policy and merge policy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    // 黑/白名单 互斥
    if (IsTrustBlockConflict(policyType, flag, allpolicies)) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }

    std::vector<std::string> &numberList = policies[policyType].numberList;
    // 合并去重
    policies[policyType].numberList = MergeAndRemoveDuplicates(numberList, addList);
    policies[policyType].policyFlag = flag;

    for (auto policy : policies) {
        if (mergePolicies.find(policy.first) == mergePolicies.end()) {
            mergePolicies[policy.first] = policy.second;
            continue;
        }
        mergePolicies[policy.first].numberList = MergeAndRemoveDuplicates(mergePolicies[policy.first].numberList,
            policy.second.numberList);
        mergePolicies[policy.first].policyFlag = policy.second.policyFlag;
    }
    return ERR_OK;
}

ErrCode TelephonySmsPolicyPlugin::RemoveCurrentAndMergePolicy(
    std::map<std::string, TelephonySmsPolicyType> &policies,
    std::map<std::string, TelephonySmsPolicyType> &mergePolicies, const std::string &policyType,
    const int32_t flag, const std::vector<std::string> &addList)
{
    auto iter = policies.find(policyType);
    if (iter == policies.end() || policies[policyType].policyFlag != flag) {
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }

    std::vector<std::string> numberList = policies[policyType].numberList;
    for (auto it = addList.begin(); it != addList.end(); ++it) {
        numberList.erase(std::remove(numberList.begin(), numberList.end(), *it), numberList.end());
    }
    policies[policyType].numberList = numberList;

    for (auto policy : policies) {
        if (mergePolicies.find(policy.first) == mergePolicies.end()) {
            mergePolicies[policy.first] = policy.second;
            continue;
        }
        mergePolicies[policy.first].numberList = MergeAndRemoveDuplicates(mergePolicies[policy.first].numberList,
            policy.second.numberList);
        mergePolicies[policy.first].policyFlag = policy.second.policyFlag;
    }
    return ERR_OK;
}

ErrCode TelephonySmsPolicyPlugin::GetOthersMergePolicyData(const std::string &adminName, int32_t userId,
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
    std::map<std::string, TelephonySmsPolicyType> mergeData;
    auto serializer = TelephonySmsPolicySerializer::GetInstance();
    for (const auto &item : adminValues) {
        std::map<std::string, TelephonySmsPolicyType> dataItem;
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
            mergeData[item.first].numberList = MergeAndRemoveDuplicates(mergeData[item.first].numberList,
                item.second.numberList);
            mergeData[item.first].policyFlag = item.second.policyFlag;
        }
    }

    if (!serializer->Serialize(mergeData, othersMergePolicyData)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode TelephonySmsPolicyPlugin::OnAdminRemove(const std::string &adminName,
    const std::string &policyData, const std::string &mergeData, int32_t userId)
{
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS