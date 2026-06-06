/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "disable_user_mtp_client_plugin.h"

#include <ipc_skeleton.h>
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "os_account_manager.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisableUserMtpClientPlugin>());
const std::string PERSIST_EDM_MTP_CLIENT_DISABLE = "persist.edm.mtp_client_disable";
const std::string CONSTRAINT_MTP_CLIENT_WRITE = "constraint.mtp.client.write"; // mtpClient 只读

DisableUserMtpClientPlugin::DisableUserMtpClientPlugin()
{
    EDMLOGI("DisableUserMtpClientPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISABLE_USER_MTP_CLIENT;
    policyName_ = PolicyName::POLICY_DISABLED_USER_MTP_CLIENT;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode DisableUserMtpClientPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisableUserMtpClientPlugin::SetMtpClientPolicy, policy: %{public}d", data);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_MTP_CLIENT_WRITE);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(constraints, data, userId,
        EdmConstants::DEFAULT_USER_ID, true);
    if (FAILED(ret)) {
        EDMLOGE("DisableUserMtpClientPlugin SetSpecificOsAccountConstraints ret: %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode DisableUserMtpClientPlugin::CheckConflictPolicy(int32_t userId)
{
    std::string value = system::GetParameter(PERSIST_EDM_MTP_CLIENT_DISABLE, "false");
    if (value == "true") { // 设备级接口禁用，返回策略冲突
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
