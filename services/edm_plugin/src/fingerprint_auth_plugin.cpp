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
#include "plugin_manager.h"
#include "user_auth_client.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = PluginManager::GetInstance()->AddPlugin(std::make_shared<FingerprintAuthPlugin>());
FingerprintAuthPlugin::FingerprintAuthPlugin()
{
    policyCode_ = EdmInterfaceCode::FINGERPRINT_AUTH;
    policyName_ = "fingerprint_auth";
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS");
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode FingerprintAuthPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("FingerprintAuthPlugin OnSetPolicy");
    auto serializer_ = FingerprintPolicySerializer::GetInstance();
    FingerprintPolicy policy;
    serializer_->Deserialize(policyData.policyData, policy);
    std::string type = data.ReadString();
    bool disallow = data.ReadBool();
    ErrCode ret = ERR_INVALID_VALUE;
    if (type == EdmConstants::FINGERPRINT_AUTH_TYPE) {
        ret = HandleFingerprintAuthPolicy(disallow, policy);
    } else if (type == EdmConstants::DISALLOW_FOR_ACCOUNT_TYPE) {
        int32_t accountId = data.ReadInt32();
        ret = HandleFingerprintForAccountPolicy(disallow, accountId, policy);
    }

    if (ret != ERR_OK) {
        return ret;
    }

    ret = SetGlobalConfigParam(policy);
    if (ret != ERR_OK) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }

    std::string afterHandle;
    if (!serializer_->Serialize(policy, afterHandle)) {
        EDMLOGE("FingerprintAuthPlugin Serialize failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    policyData.isChanged = (afterHandle != policyData.policyData);
    if (policyData.isChanged) {
        policyData.policyData = afterHandle;
    }
    return ERR_OK;
}

ErrCode FingerprintAuthPlugin::HandleFingerprintAuthPolicy(bool disallow, FingerprintPolicy &policy)
{
    if (disallow) {
        policy.globalDisallow = true;
        policy.accountIds.clear();
        return ERR_OK;
    }
    if (policy.accountIds.size() != 0) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    policy.globalDisallow = false;
    return ERR_OK;
}

ErrCode FingerprintAuthPlugin::HandleFingerprintForAccountPolicy(bool disallow,
    int32_t accountId, FingerprintPolicy &policy)
{
    if (policy.globalDisallow) {
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    if (disallow) {
        policy.accountIds.insert(accountId);
    } else {
        auto it = policy.accountIds.find(accountId);
        if (it != policy.accountIds.end()) {
            policy.accountIds.erase(it);
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
} // namespace EDM
} // namespace OHOS
