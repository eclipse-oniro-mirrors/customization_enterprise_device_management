/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "user_ext_credential_plugin.h"
#include "account_iam_client.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code.h"
#include "iplugin_manager.h"
#include "securec.h"
#include "ukey_iam_error_converter.h"

#include <chrono>
#include <condition_variable>
#include <mutex>

namespace OHOS {
namespace EDM {

namespace {

class CredentialIDMCallback : public AccountSA::IDMCallback {
public:
    virtual ~CredentialIDMCallback() = default;
    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const AccountSA::Attributes &extraInfo) override {}
    void OnResult(int32_t result, const AccountSA::Attributes &extraInfo) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        resultCode_ = result;
        extraInfo.GetUint64Value(AccountSA::Attributes::ATTR_CREDENTIAL_ID, credentialId_);
        done_ = true;
        cv_.notify_one();
    }

    int32_t WaitResult(int32_t timeoutMs = 5000)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), [this] { return done_; })) {
            return resultCode_;
        }
        return -1;
    }

    int32_t resultCode_ = 0;
    uint64_t credentialId_ = 0;
    bool done_ = false;
    std::mutex mutex_;
    std::condition_variable cv_;
};

class CredInfoCallback : public AccountSA::GetCredInfoCallback {
public:
    virtual ~CredInfoCallback() = default;
    void OnCredentialInfo(int32_t result, const std::vector<AccountSA::CredentialInfo> &infoList) override
    {
        std::lock_guard<std::mutex> lock(mutex_);
        resultCode_ = result;
        infoList_ = infoList;
        done_ = true;
        cv_.notify_one();
    }

    int32_t WaitResult(int32_t timeoutMs = 5000)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (cv_.wait_for(lock, std::chrono::milliseconds(timeoutMs), [this] { return done_; })) {
            return resultCode_;
        }
        return -1;
    }

    int32_t resultCode_ = 0;
    bool done_ = false;
    std::vector<AccountSA::CredentialInfo> infoList_;
    std::mutex mutex_;
    std::condition_variable cv_;
};
} // namespace

const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<UserExtCredentialPlugin>());

UserExtCredentialPlugin::UserExtCredentialPlugin()
{
    EDMLOGI("UserExtCredentialPlugin init");
    policyCode_ = EdmInterfaceCode::USER_EXT_CREDENTIAL;
    policyName_ = PolicyName::POLICY_USER_EXT_CREDENTIAL;
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode UserExtCredentialPlugin::HandleAddCredential(MessageParcel &data, MessageParcel &reply)
{
    std::string pluginInfo = data.ReadString();
    std::vector<uint8_t> authToken;
    data.ReadUInt8Vector(&authToken);
    int32_t accountId = data.ReadInt32();
    EDMLOGI("UserExtCredentialPlugin AddCredential pluginInfo: %{public}s, accountId: %{public}d",
        pluginInfo.c_str(), accountId);
    auto callback = std::make_shared<CredentialIDMCallback>();
    AccountSA::CredentialParameters credInfo{};
    credInfo.authType = AccountSA::AuthType::CUSTOM_AUTH;
    credInfo.token = authToken;
    credInfo.additionalInfo = pluginInfo;
    CallAddCredential(accountId, credInfo, callback);
    int32_t ret = callback->WaitResult();
    if (ret != ERR_OK) {
        std::string errMsg;
        ErrCode edmErrCode = ConvertIamError(ret, errMsg);
        EDMLOGE("UserExtCredentialPlugin AddCredential failed, ret: %{public}d, edmErrCode: %{public}d, "
            "accountId: %{public}d, errMsg: %{public}s", ret, edmErrCode, accountId, errMsg.c_str());
        reply.WriteInt32(edmErrCode);
        reply.WriteString(errMsg);
        return edmErrCode;
    }
    reply.WriteInt32(ret);
    uint64_t credentialId = callback->credentialId_;
    std::vector<uint8_t> credIdVec(sizeof(uint64_t));
    if (memcpy_s(credIdVec.data(), sizeof(uint64_t), &credentialId, sizeof(uint64_t)) != EOK) {
        EDMLOGE("UserExtCredentialPlugin AddCredential memcpy_s failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    reply.WriteUInt8Vector(credIdVec);
    return ERR_OK;
}

ErrCode UserExtCredentialPlugin::HandleRemoveCredential(MessageParcel &data, MessageParcel &reply)
{
    std::vector<uint8_t> credIdVec;
    data.ReadUInt8Vector(&credIdVec);
    if (credIdVec.size() < sizeof(uint64_t)) {
        EDMLOGE("UserExtCredentialPlugin DelCred invalid credentialId size: %{public}zu", credIdVec.size());
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    uint64_t credentialId = 0;
    if (memcpy_s(&credentialId, sizeof(uint64_t), credIdVec.data(), sizeof(uint64_t)) != EOK) {
        EDMLOGE("UserExtCredentialPlugin DelCred memcpy_s failed");
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    std::vector<uint8_t> authToken;
    data.ReadUInt8Vector(&authToken);
    int32_t accountId = data.ReadInt32();
    EDMLOGI("UserExtCredentialPlugin DelCred credentialId: %{public}llu, accountId: %{public}d",
        static_cast<unsigned long long>(credentialId), accountId);
    auto callback = std::make_shared<CredentialIDMCallback>();
    CallDelCred(accountId, credentialId, authToken, callback);
    int32_t ret = callback->WaitResult();
    if (ret != ERR_OK) {
        std::string errMsg;
        ErrCode edmErrCode = ConvertIamError(ret, errMsg);
        EDMLOGE("UserExtCredentialPlugin DelCred failed, ret: %{public}d, edmErrCode: %{public}d, "
            "accountId: %{public}d, credentialId: %{public}llu, errMsg: %{public}s",
            ret, edmErrCode, accountId, static_cast<unsigned long long>(credentialId), errMsg.c_str());
        reply.WriteInt32(edmErrCode);
        reply.WriteString(errMsg);
        return edmErrCode;
    }
    reply.WriteInt32(ret);
    return ERR_OK;
}

ErrCode UserExtCredentialPlugin::OnHandlePolicy(uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("UserExtCredentialPlugin::OnHandlePolicy");
    uint32_t operateType = FUNC_TO_OPERATE(funcCode);
    if (operateType == static_cast<uint32_t>(FuncOperateType::SET)) {
        return HandleAddCredential(data, reply);
    } else if (operateType == static_cast<uint32_t>(FuncOperateType::REMOVE)) {
        return HandleRemoveCredential(data, reply);
    }
    return ERR_INVALID_VALUE;
}

ErrCode UserExtCredentialPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    int32_t accountId = data.ReadInt32();
    EDMLOGI("UserExtCredentialPlugin::OnGetPolicy accountId: %{public}d", accountId);
    auto callback = std::make_shared<CredInfoCallback>();
    CallGetCredentialInfo(
        accountId, static_cast<int32_t>(AccountSA::AuthType::CUSTOM_AUTH), callback);
    int32_t ret = callback->WaitResult();
    if (ret != ERR_OK) {
        std::string errMsg;
        ErrCode edmErrCode = ConvertIamError(ret, errMsg);
        EDMLOGE("UserExtCredentialPlugin GetCredentialInfo failed, ret: %{public}d, edmErrCode: %{public}d, "
            "accountId: %{public}d, errMsg: %{public}s", ret, edmErrCode, accountId, errMsg.c_str());
        reply.WriteInt32(edmErrCode);
        reply.WriteString(errMsg);
        return edmErrCode;
    }
    reply.WriteInt32(ret);
    int32_t count = static_cast<int32_t>(callback->infoList_.size());
    reply.WriteInt32(count);
    for (const auto &info : callback->infoList_) {
        std::vector<uint8_t> credIdVec(sizeof(uint64_t));
        if (memcpy_s(credIdVec.data(), sizeof(uint64_t), &info.credentialId, sizeof(uint64_t)) != EOK) {
            EDMLOGE("UserExtCredentialPlugin OnGetPolicy memcpy_s failed");
            return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
        }
        reply.WriteUInt8Vector(credIdVec);
    }
    return ERR_OK;
}

void UserExtCredentialPlugin::CallAddCredential(int32_t accountId,
    const AccountSA::CredentialParameters &credInfo,
    const std::shared_ptr<AccountSA::IDMCallback> &callback)
{
    AccountSA::AccountIAMClient::GetInstance().AddCredential(accountId, credInfo, callback);
}

void UserExtCredentialPlugin::CallDelCred(int32_t accountId, uint64_t credentialId,
    const std::vector<uint8_t> &authToken,
    const std::shared_ptr<AccountSA::IDMCallback> &callback)
{
    AccountSA::AccountIAMClient::GetInstance().DelCred(accountId, credentialId, authToken, callback);
}

int32_t UserExtCredentialPlugin::CallGetCredentialInfo(int32_t accountId, int32_t authType,
    const std::shared_ptr<AccountSA::GetCredInfoCallback> &callback)
{
    return AccountSA::AccountIAMClient::GetInstance().GetCredentialInfo(
        accountId, static_cast<AccountSA::AuthType>(authType), callback);
}
} // namespace EDM
} // namespace OHOS
