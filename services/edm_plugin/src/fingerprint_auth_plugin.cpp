/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "fingerprint_auth_plugin.h"

#include "edm_ipc_interface_code.h"
#include "fingerprint_policy_serializer.h"
#include "iplugin_manager.h"
#include "ipolicy_manager.h"
#include "user_auth_client.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<FingerprintAuthPlugin>());
FingerprintAuthPlugin::FingerprintAuthPlugin()
{
    policyCode_ = EdmInterfaceCode::FINGERPRINT_AUTH;
    policyName_ = PolicyName::POLICY_FINGERPRINT_AUTH;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode FingerprintAuthPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("FingerprintAuthPlugin OnSetPolicy");
    std::string type = data.ReadString();
    bool disallow = data.ReadBool();
    ErrCode ret = ERR_INVALID_VALUE;
    auto serializer = FingerprintPolicySerializer::GetInstance();
    FingerprintPolicy currentPolicy;
    FingerprintPolicy mergePolicy;
    if (!serializer->Deserialize(policyData.policyData, currentPolicy) ||
        !serializer->Deserialize(policyData.mergePolicyData, mergePolicy)) {
        EDMLOGE("FingerprintAuthPlugin::OnHandlePolicy Deserialize current policy and merge policy failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (type == EdmConstants::FINGERPRINT_AUTH_TYPE) {
        ret = HandleFingerprintAuthPolicy(disallow, currentPolicy, mergePolicy);
    } else if (type == EdmConstants::DISALLOW_FOR_ACCOUNT_TYPE) {
        int32_t accountId = data.ReadInt32();
        ret = HandleFingerprintForAccountPolicy(disallow, accountId, currentPolicy, mergePolicy);
    }
    if (ret != ERR_OK) {
        return ret;
    }
    ret = SetGlobalConfigParam(mergePolicy);
    if (ret != ERR_OK) {
        EDMLOGE("FingerprintAuthPlugin::OnHandlePolicy SetGlobalConfigParam fail.ret: %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    std::string afterHandle;
    std::string afterMerge;
    if (!serializer->Serialize(currentPolicy, afterHandle) || !serializer->Serialize(mergePolicy, afterMerge)) {
        EDMLOGE("FingerprintAuthPlugin Serialize current policy and merge policy failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    policyData.isChanged = (afterHandle != policyData.policyData);
    if (policyData.isChanged) {
        policyData.policyData = afterHandle;
    }
    policyData.mergePolicyData = afterMerge;
    return ERR_OK;
}

ErrCode FingerprintAuthPlugin::HandleFingerprintAuthPolicy(bool disallow, FingerprintPolicy &currentPolicy,
    FingerprintPolicy &mergePolicy)
{
    if (disallow) {
        currentPolicy.globalDisallow = true;
        currentPolicy.accountIds.clear();
        mergePolicy.globalDisallow = true;
        mergePolicy.accountIds.clear();
        return ERR_OK;
    }
    if (!currentPolicy.accountIds.empty()) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    currentPolicy.globalDisallow = false;
    return ERR_OK;
}

ErrCode FingerprintAuthPlugin::HandleFingerprintForAccountPolicy(bool disallow, int32_t accountId,
    FingerprintPolicy &currentPolicy, FingerprintPolicy &mergePolicy)
{
    if (currentPolicy.globalDisallow) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    if (disallow) {
        currentPolicy.accountIds.insert(accountId);
    } else {
        auto it = currentPolicy.accountIds.find(accountId);
        if (it != currentPolicy.accountIds.end()) {
            currentPolicy.accountIds.erase(it);
        }
    }
    if (!mergePolicy.globalDisallow) {
        for (auto item : currentPolicy.accountIds) {
            mergePolicy.accountIds.insert(item);
        }
    }
    return ERR_OK;
}

ErrCode FingerprintAuthPlugin::SetGlobalConfigParam(FingerprintPolicy policy)
{
    std::vector<int32_t> userIds(policy.accountIds.size());
    std::copy(policy.accountIds.begin(), policy.accountIds.end(), userIds.begin());
    UserIam::UserAuth::GlobalConfigParam param;
    param.userIds = userIds;
    param.authTypes.push_back(UserIam::UserAuth::AuthType::FINGERPRINT);
    param.type = UserIam::UserAuth::GlobalConfigType::ENABLE_STATUS;
    param.value.enableStatus = !policy.globalDisallow && userIds.size() == 0;
    return UserIam::UserAuth::UserAuthClient::GetInstance().SetGlobalConfigParam(param);
}

ErrCode FingerprintAuthPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    EDMLOGI("FingerprintAuthPlugin OnGetPolicy");
    auto serializer_ = FingerprintPolicySerializer::GetInstance();
    FingerprintPolicy policy;
    serializer_->Deserialize(policyData, policy);
    std::string type = data.ReadString();
    bool isDisallow = false;
    if (type == EdmConstants::FINGERPRINT_AUTH_TYPE) {
        isDisallow = policy.globalDisallow;
    } else if (type == EdmConstants::DISALLOW_FOR_ACCOUNT_TYPE) {
        int32_t accountId = data.ReadInt32();
        auto it = policy.accountIds.find(accountId);
        isDisallow = (it != policy.accountIds.end());
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteBool(isDisallow);
    EDMLOGI("FingerprintAuthPlugin OnGetPolicy result %{public}d", isDisallow);
    return ERR_OK;
}

ErrCode FingerprintAuthPlugin::GetOthersMergePolicyData(const std::string &adminName,
    std::string &othersMergePolicyData)
{
    std::unordered_map<std::string, std::string> adminValues;
    IPolicyManager::GetInstance()->GetAdminByPolicyName(GetPolicyName(), adminValues);
    EDMLOGI("FingerprintAuthPlugin::GetOthersMergePolicyData %{public}s value size %{public}d.",
        GetPolicyName().c_str(), (uint32_t)adminValues.size());
    if (adminValues.empty()) {
        return ERR_OK;
    }
    auto entry = adminValues.find(adminName);
    // Remove the current admin policy value from the cache map.
    if (entry != adminValues.end()) {
        adminValues.erase(entry);
    }
    if (adminValues.empty()) {
        return ERR_OK;
    }
    auto serializer = FingerprintPolicySerializer::GetInstance();
    std::vector<FingerprintPolicy> data;
    for (const auto &item : adminValues) {
        FingerprintPolicy dataItem;
        if (!item.second.empty()) {
            if (!serializer->Deserialize(item.second, dataItem)) {
                return EdmReturnErrCode::SYSTEM_ABNORMALLY;
            }
            data.push_back(dataItem);
        }
    }
    FingerprintPolicy result;
    if (!serializer->MergePolicy(data, result)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    if (!serializer->Serialize(result, othersMergePolicyData)) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode FingerprintAuthPlugin::OnAdminRemove(const std::string &adminName, const std::string &policyData,
    const std::string &mergeData, int32_t userId)
{
    FingerprintPolicy policy;
    FingerprintPolicySerializer::GetInstance()->Deserialize(mergeData, policy);
    ErrCode ret = SetGlobalConfigParam(policy);
    if (ret != ERR_OK) {
        EDMLOGE("FingerprintAuthPlugin OnAdminRemove set global config param failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

void FingerprintAuthPlugin::OnOtherServiceStart()
{
    std::string policyData;
    IPolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_FINGERPRINT_AUTH,
        policyData, EdmConstants::DEFAULT_USER_ID);
    auto serializer_ = FingerprintPolicySerializer::GetInstance();
    FingerprintPolicy policy;
    serializer_->Deserialize(policyData, policy);
    int32_t ret = SetGlobalConfigParam(policy);
    if (ret != ERR_OK) {
        EDMLOGE("FingerprintAuthPlugin::OnOtherServiceStart SetGlobalConfigParam fail.ret: %{public}d", ret);
    }
}
} // namespace EDM
} // namespace OHOS
