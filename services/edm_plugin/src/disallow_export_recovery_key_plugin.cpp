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

#include "disallow_export_recovery_key_plugin.h"

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
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    DisallowExportRecoveryKeyPlugin::GetPlugin());
const std::string CONSTRAINT_RECOVERY_KEY = "constraint.recoveryKey";

void DisallowExportRecoveryKeyPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowExportRecoveryKeyPlugin, bool>> ptr)
{
    EDMLOGI("DisallowExportRecoveryKeyPlugin InitPlugin...");
    ptr->InitAttribute(
        EdmInterfaceCode::DISALLOWED_EXPORT_RECOVERY_KEY,
        PolicyName::POLICY_DISALLOWED_EXPORT_RECOVERY_KEY,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowExportRecoveryKeyPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowExportRecoveryKeyPlugin::OnAdminRemove);
}

ErrCode DisallowExportRecoveryKeyPlugin::OnSetPolicy(
    bool &data, bool &currentData, bool &mergeData, int32_t userId)
{
    EDMLOGI("DisallowExportRecoveryKeyPlugin::OnSetPolicy, data: %{public}d, currentData: %{public}d, "
            "mergeData: %{public}d,userId: %{public}d", data, currentData, mergeData, userId);
    if (mergeData) {
        currentData = data;
        return ERR_OK;
    }
    ErrCode ret = SetExportRecoveryKeyPolicy(data, userId);
    if (FAILED(ret)) {
        EDMLOGE("DisallowExportRecoveryKeyPlugin::OnSetPolicy Failed, ret: %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = data;
    mergeData = data;
    return ERR_OK;
}

ErrCode DisallowExportRecoveryKeyPlugin::OnAdminRemove(
    const std::string &adminName, bool &data, bool &mergeData, int32_t userId)
{
    EDMLOGI("DisallowExportRecoveryKeyPlugin::OnAdminRemove, adminName: %{public}s, data: %{public}d, "
            "mergeData: %{public}d, userId: %{public}d", adminName.c_str(), data, mergeData, userId);
    if (mergeData) {
        return ERR_OK;
    }
    if (data) {
        ErrCode ret = SetExportRecoveryKeyPolicy(false, userId);
        if (FAILED(ret)) {
            EDMLOGE("DisallowExportRecoveryKeyPlugin::OnAdminRemove Failed, ret: %{public}d", ret);
        }
    }
    return ERR_OK;
}

ErrCode DisallowExportRecoveryKeyPlugin::SetExportRecoveryKeyPolicy(bool policy, int32_t userId)
{
    EDMLOGI("DisallowExportRecoveryKeyPlugin::SetExportRecoveryKeyPolicy, "
            "userId: %{public}d, policy: %{public}d", userId, policy);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_RECOVERY_KEY);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(
        constraints, policy, userId, EdmConstants::DEFAULT_USER_ID, true);
    EDMLOGI("DisallowExportRecoveryKeyPlugin SetSpecificOsAccountConstraints ret: %{public}d", ret);
    return ret;
}
} // namespace EDM
} // namespace OHOS
