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

#include "user_ext_session_plugin.h"
#include "account_iam_client.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "func_code.h"
#include "iplugin_manager.h"
#include "ukey_iam_error_converter.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<UserExtSessionPlugin>());

UserExtSessionPlugin::UserExtSessionPlugin()
{
    EDMLOGI("UserExtSessionPlugin init");
    policyCode_ = EdmInterfaceCode::USER_EXT_SESSION;
    policyName_ = PolicyName::POLICY_USER_EXT_SESSION;
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode UserExtSessionPlugin::OnHandlePolicy(uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    int32_t accountId = data.ReadInt32();
    uint32_t operateType = FUNC_TO_OPERATE(funcCode);
    if (operateType == static_cast<uint32_t>(FuncOperateType::SET)) {
        EDMLOGI("UserExtSessionPlugin::OpenSession accountId: %{public}d", accountId);
        std::vector<uint8_t> challenge;
        int32_t ret = CallOpenSession(accountId, challenge);
        if (ret != ERR_OK) {
            std::string errMsg;
            ErrCode edmErrCode = ConvertIamError(ret, errMsg);
            EDMLOGE("UserExtSessionPlugin OpenSession failed, ret: %{public}d, edmErrCode: %{public}d, "
                "accountId: %{public}d, errMsg: %{public}s", ret, edmErrCode, accountId, errMsg.c_str());
            reply.WriteInt32(edmErrCode);
            reply.WriteString(errMsg);
            return edmErrCode;
        }
        reply.WriteInt32(ret);
        reply.WriteUInt8Vector(challenge);
        return ERR_OK;
    } else if (operateType == static_cast<uint32_t>(FuncOperateType::REMOVE)) {
        EDMLOGI("UserExtSessionPlugin::CloseSession accountId: %{public}d", accountId);
        int32_t ret = CallCloseSession(accountId);
        if (ret != ERR_OK) {
            std::string errMsg;
            ErrCode edmErrCode = ConvertIamError(ret, errMsg);
            EDMLOGE("UserExtSessionPlugin CloseSession failed, ret: %{public}d, edmErrCode: %{public}d, "
                "accountId: %{public}d, errMsg: %{public}s", ret, edmErrCode, accountId, errMsg.c_str());
            reply.WriteInt32(edmErrCode);
            reply.WriteString(errMsg);
            return edmErrCode;
        }
        reply.WriteInt32(ret);
        return ERR_OK;
    }

    return ERR_INVALID_VALUE;
}

int32_t UserExtSessionPlugin::CallOpenSession(int32_t accountId, std::vector<uint8_t> &challenge)
{
    return AccountSA::AccountIAMClient::GetInstance().OpenSession(accountId, challenge);
}

int32_t UserExtSessionPlugin::CallCloseSession(int32_t accountId)
{
    return AccountSA::AccountIAMClient::GetInstance().CloseSession(accountId);
}
} // namespace EDM
} // namespace OHOS
