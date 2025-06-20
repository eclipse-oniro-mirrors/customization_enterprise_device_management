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

#include "disable_sudo_plugin.h"

#include <ipc_skeleton.h>
#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "os_account_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableSudoPlugin::GetPlugin());
const std::string CONSTRAINT_SUDO = "constraint.sudo";

void DisableSudoPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableSudoPlugin, bool>> ptr)
{
    EDMLOGI("DisableSudoPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_SUDO, PolicyName::POLICY_DISABLED_SUDO,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableSudoPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableSudoPlugin::OnAdminRemove);
}

ErrCode DisableSudoPlugin::OnSetPolicy(bool &data, bool &currentData, bool &mergeData,
    int32_t userId)
{
    EDMLOGI("DisableSudoPlugin::OnSetPolicy, data: %{public}d, currentData: %{public}d, "
            "mergeData: %{public}d,userId: %{public}d", data, currentData, mergeData, userId);
    if (mergeData) {
        currentData = data;
        return ERR_OK;
    }
    ErrCode ret = SetSudoPolicy(data, userId);
    EDMLOGI("DisableSudoPlugin::OnSetPolicy, SetSudoPolicy ret: %{public}d", ret);
    if (FAILED(ret)) {
        EDMLOGE("DisableSudoPlugin::OnSetPolicy, SetSudoPolicy failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = data;
    mergeData = data;
    return ERR_OK;
}

ErrCode DisableSudoPlugin::OnAdminRemove(const std::string &adminName, bool &data, bool &mergeData,
    int32_t userId)
{
    EDMLOGI("DisableSudoPlugin::OnAdminRemove, adminName: %{public}s, data: %{public}d, "
            "mergeData: %{public}d, userId: %{public}d", adminName.c_str(), data, mergeData, userId);
    if (mergeData) {
        return ERR_OK;
    }
    // admin 移除时，综合策略为读写，且移除的策略为只读，则更新策略为读写
    if (!mergeData && data) {
        ErrCode ret = SetSudoPolicy(false, userId);
        EDMLOGI("DisableSudoPlugin::OnAdminRemove, SetSudoPolicy ret: %{public}d", ret);
        if (FAILED(ret)) {
            EDMLOGE("DisableSudoPlugin::OnAdminRemove, SetSudoPolicy failed");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

ErrCode DisableSudoPlugin::SetSudoPolicy(bool policy, int32_t userId)
{
    EDMLOGI("DisableSudoPlugin::SetSudoPolicy, userId: %{public}d, policy: %{public}d", userId, policy);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_SUDO);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(constraints, policy, userId,
        EdmConstants::DEFAULT_USER_ID, true);
    EDMLOGI("DisableSudoPlugin::SetSudoPolicy, SetSpecificOsAccountConstraints ret: %{public}d", ret);
    return ret;
}
} // namespace EDM
} // namespace OHOS