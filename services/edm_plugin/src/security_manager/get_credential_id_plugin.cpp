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

#include "get_credential_id_plugin.h"

#include <memory>
#include <utility>
#include <vector>

#include "securec.h"

#include "attributes.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "iam_common_defines.h"
#include "user_access_ctrl_client.h"
#include "user_access_ctrl_client_callback.h"
#include "verify_auth_token_callback.h"

namespace OHOS {
namespace EDM {

namespace {
constexpr int64_t IAM_VERIFY_TIMEOUT_MS = 5000;

class SensitiveBufferCleaner {
public:
    explicit SensitiveBufferCleaner(std::vector<uint8_t> &buf) : buf_(buf) {}
    ~SensitiveBufferCleaner()
    {
        if (!buf_.empty()) {
            (void)memset_s(buf_.data(), buf_.size(), 0, buf_.size());
            buf_.clear();
        }
    }

private:
    std::vector<uint8_t> &buf_;
};
} // namespace

const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<GetCredentialIdPlugin>());

GetCredentialIdPlugin::GetCredentialIdPlugin()
{
    EDMLOGI("GetCredentialIdPlugin init");
    policyCode_ = EdmInterfaceCode::GET_CREDENTIAL_ID;
    policyName_ = PolicyName::POLICY_GET_CREDENTIAL_ID;
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode GetCredentialIdPlugin::OnHandlePolicy(uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("GetCredentialIdPlugin::OnHandlePolicy");
    return ERR_INVALID_VALUE;
}

ErrCode GetCredentialIdPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("GetCredentialIdPlugin::OnGetPolicy");
    std::vector<uint8_t> authToken;
    SensitiveBufferCleaner cleaner(authToken);
    if (!data.ReadUInt8Vector(&authToken)) {
        EDMLOGE("GetCredentialIdPlugin: read authToken failed.");
        reply.WriteInt32(EdmReturnErrCode::EXECUTE_TIME_OUT);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    uint64_t allowableDuration = 0;
    if (!data.ReadUint64(allowableDuration)) {
        EDMLOGE("GetCredentialIdPlugin: read allowableDuration failed.");
        reply.WriteInt32(EdmReturnErrCode::EXECUTE_TIME_OUT);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    EDMLOGI("GetCredentialIdPlugin::OnGetPolicy authToken size: %{public}zu, allowableDuration: %{public}llu",
        authToken.size(), static_cast<unsigned long long>(allowableDuration));

    if (authToken.empty()) {
        EDMLOGE("GetCredentialIdPlugin: the authToken is empty.");
        reply.WriteInt32(EdmReturnErrCode::AUTH_TOKEN_INVALID);
        return EdmReturnErrCode::AUTH_TOKEN_INVALID;
    }
    if (authToken.size() > EdmConstants::SecurityManager::MAX_AUTH_TOKEN_SIZE) {
        EDMLOGE("GetCredentialIdPlugin: the authToken exceeds the maximum size.");
        reply.WriteInt32(EdmReturnErrCode::AUTH_TOKEN_INVALID);
        return EdmReturnErrCode::AUTH_TOKEN_INVALID;
    }
    if (allowableDuration == 0 || allowableDuration > EdmConstants::SecurityManager::MAX_ALLOWABLE_DURATION) {
        EDMLOGE("GetCredentialIdPlugin: the allowableDuration is out of range.");
        reply.WriteInt32(EdmReturnErrCode::AUTH_TOKEN_INVALID_DURATION_INVALID);
        return EdmReturnErrCode::AUTH_TOKEN_INVALID_DURATION_INVALID;
    }

    uint64_t credentialId = 0;
    ErrCode ret = CallVerifyAuthToken(authToken, allowableDuration, credentialId);
    if (FAILED(ret)) {
        EDMLOGE("GetCredentialIdPlugin: verify auth token failed, errCode: %{public}d", ret);
        reply.WriteInt32(ret);
        return ret;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteUint64(credentialId);
    return ERR_OK;
}

ErrCode GetCredentialIdPlugin::CallVerifyAuthToken(const std::vector<uint8_t> &authToken, uint64_t allowableDuration,
    uint64_t &credentialId)
{
    auto callback = std::make_shared<VerifyAuthTokenCallback>();
    UserIam::UserAuth::UserAccessCtrlClient::GetInstance().VerifyAuthToken(authToken, allowableDuration, callback);
    int32_t ret = callback->WaitResult(IAM_VERIFY_TIMEOUT_MS);
    if (ret == -1) {
        EDMLOGE("GetCredentialIdPlugin: verify auth token timed out.");
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    if (ret != static_cast<int32_t>(UserIam::UserAuth::SUCCESS)) {
        EDMLOGE("GetCredentialIdPlugin: verify auth token failed, iam result: %{public}d", ret);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    credentialId = callback->GetCredentialId();
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
