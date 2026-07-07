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

#include "unlock_policy_plugin.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "screenlock_manager.h"
#include "unlock_policy.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<UnlockPolicyPlugin>());

UnlockPolicyPlugin::UnlockPolicyPlugin()
{
    EDMLOGI("UnlockPolicyPlugin init");
    policyCode_ = EdmInterfaceCode::UNLOCK_POLICY;
    policyName_ = PolicyName::POLICY_UNLOCK_POLICY;
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SECURITY);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode UnlockPolicyPlugin::OnHandlePolicy(uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    int32_t policy = data.ReadInt32();
    int32_t accountId = data.ReadInt32();
    EDMLOGI("UnlockPolicyPlugin OnHandlePolicy policy: %{public}d, accountId: %{public}d", policy, accountId);
    if (policy != static_cast<int32_t>(UnlockPolicyType::DEFAULT) &&
        policy != static_cast<int32_t>(UnlockPolicyType::EXTENDED_AUTH_ONLY) &&
        policy != static_cast<int32_t>(UnlockPolicyType::EXTENDED_AUTH_REQUIRED)) {
        EDMLOGE("UnlockPolicyPlugin invalid policy value: %{public}d", policy);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    int32_t ret = ScreenLock::ScreenLockManager::GetInstance()->SetUnlockPolicy(accountId, policy);
    if (ret != ScreenLock::E_SCREENLOCK_OK) {
        EDMLOGE("UnlockPolicyPlugin SetUnlockPolicy failed, ret: %{public}d", ret);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    return ERR_OK;
}

ErrCode UnlockPolicyPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    int32_t accountId = data.ReadInt32();
    EDMLOGI("UnlockPolicyPlugin::OnGetPolicy accountId: %{public}d", accountId);
    int32_t policy = 0;
    int32_t ret = ScreenLock::ScreenLockManager::GetInstance()->GetUnlockPolicy(accountId, policy);
    if (ret != ScreenLock::E_SCREENLOCK_OK) {
        EDMLOGE("UnlockPolicyPlugin GetUnlockPolicy failed, ret: %{public}d", ret);
        reply.WriteInt32(EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED);
        return EdmReturnErrCode::PARAMETER_VERIFICATION_FAILED;
    }
    reply.WriteInt32(ERR_OK);
    reply.WriteInt32(policy);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
