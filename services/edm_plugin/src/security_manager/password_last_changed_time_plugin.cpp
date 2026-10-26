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

#include "password_last_changed_time_plugin.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "edm_os_account_manager_impl.h"
#include "iam_common_defines.h"
#include "iplugin_manager.h"
#include "user_idm_client.h"

namespace OHOS {
namespace EDM {

namespace {
// IAM returns this code when the user has no PIN credential. The plugin maps it to the upstream
// INTERFACE_UNSUPPORTED(801) error code.
constexpr int32_t IAM_CAPABILITY_NOT_SUPPORTED =
    static_cast<int32_t>(UserIam::UserAuth::CAPABILITY_NOT_SUPPORTED);
} // namespace

const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<PasswordLastChangedTimePlugin>());

PasswordLastChangedTimePlugin::PasswordLastChangedTimePlugin()
{
    EDMLOGI("PasswordLastChangedTimePlugin init");
    policyCode_ = EdmInterfaceCode::PASSWORD_LAST_CHANGED_TIME;
    policyName_ = PolicyName::POLICY_PASSWORD_LAST_CHANGED_TIME;
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode PasswordLastChangedTimePlugin::OnHandlePolicy(uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("PasswordLastChangedTimePlugin::OnHandlePolicy");
    return ERR_INVALID_VALUE;
}

ErrCode PasswordLastChangedTimePlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    int32_t accountId = data.ReadInt32();
    EDMLOGI("PasswordLastChangedTimePlugin::OnGetPolicy accountId: %{public}d", accountId);
    if (accountId < 0) {
        EDMLOGE("PasswordLastChangedTimePlugin invalid accountId: %{public}d", accountId);
        reply.WriteInt32(EdmReturnErrCode::UID_INVALID);
        return EdmReturnErrCode::UID_INVALID;
    }
    bool isExist = false;
    ErrCode ret = CallIsOsAccountExists(accountId, isExist);
    if (FAILED(ret) || !isExist) {
        EDMLOGE("PasswordLastChangedTimePlugin accountId is not exist: %{public}d", accountId);
        reply.WriteInt32(EdmReturnErrCode::UID_INVALID);
        return EdmReturnErrCode::UID_INVALID;
    }
    uint64_t latestTime = 0;
    int32_t iamRet = CallGetLatestEnrollmentTime(accountId,
        static_cast<int32_t>(UserIam::UserAuth::AuthType::PIN), latestTime);
    if (iamRet != ERR_OK && iamRet != IAM_CAPABILITY_NOT_SUPPORTED) {
        ErrCode errCode = EdmReturnErrCode::EXECUTE_TIME_OUT;
        EDMLOGE("PasswordLastChangedTimePlugin GetLatestEnrollmentTime failed, ret: %{public}d, "
            "accountId: %{public}d, errCode: %{public}d", iamRet, accountId, errCode);
        reply.WriteInt32(errCode);
        return errCode;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteUint64(latestTime);
    return ERR_OK;
}

int32_t PasswordLastChangedTimePlugin::CallGetLatestEnrollmentTime(int32_t accountId, int32_t authType,
    uint64_t &latestTime)
{
    return UserIam::UserAuth::UserIdmClient::GetInstance().GetLatestEnrollmentTime(
        accountId, static_cast<UserIam::UserAuth::AuthType>(authType), latestTime);
}

ErrCode PasswordLastChangedTimePlugin::CallIsOsAccountExists(int32_t accountId, bool &isExist)
{
    return std::make_shared<EdmOsAccountManagerImpl>()->IsOsAccountExists(accountId, isExist);
}
} // namespace EDM
} // namespace OHOS
