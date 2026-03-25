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

#include "disallow_multi_window_plugin.h"

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
    DisallowMultiWindowPlugin::GetPlugin());
const std::string CONSTRAINT_MULTI_WINDOW = "constraint.multiWindow";

void DisallowMultiWindowPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowMultiWindowPlugin, bool>> ptr)
{
    EDMLOGI("DisallowMultiWindowPlugin InitPlugin...");
    ptr->InitAttribute(
        EdmInterfaceCode::DISALLOWED_MULTI_WINDOW,
        PolicyName::POLICY_DISALLOWED_MULTI_WINDOW,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowMultiWindowPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowMultiWindowPlugin::OnAdminRemove);
}

ErrCode DisallowMultiWindowPlugin::OnSetPolicy(
    bool &data, bool &currentData, bool &mergeData, int32_t userId)
{
    EDMLOGI("DisallowMultiWindowPlugin::OnSetPolicy, data: %{public}d, currentData: %{public}d, "
            "mergeData: %{public}d", data, currentData, mergeData);
    if (mergeData) {
        currentData = data;
        return ERR_OK;
    }
    ErrCode ret = SetMultiWindowPolicy(data, userId);
    if (FAILED(ret)) {
        EDMLOGE("DisallowMultiWindowPlugin::OnSetPolicy Failed, ret: %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = data;
    mergeData = data;
    return ERR_OK;
}

ErrCode DisallowMultiWindowPlugin::OnAdminRemove(
    const std::string &adminName, bool &data, bool &mergeData, int32_t userId)
{
    EDMLOGI("DisallowMultiWindowPlugin::OnAdminRemove, adminName: %{public}s, data: %{public}d, "
            "mergeData: %{public}d", adminName.c_str(), data, mergeData);
    if (mergeData) {
        return ERR_OK;
    }
    if (data) {
        ErrCode ret = SetMultiWindowPolicy(false, userId);
        if (FAILED(ret)) {
            EDMLOGE("DisallowMultiWindowPlugin::OnAdminRemove Failed, ret: %{public}d", ret);
        }
    }
    return ERR_OK;
}

ErrCode DisallowMultiWindowPlugin::SetMultiWindowPolicy(bool policy, int32_t userId)
{
    EDMLOGI("DisallowMultiWindowPlugin::SetMultiWindowPolicy, "
            "policy: %{public}d", policy);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_MULTI_WINDOW);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(
        constraints, policy, userId, EdmConstants::DEFAULT_USER_ID, true);
    EDMLOGI("DisallowMultiWindowPlugin SetSpecificOsAccountConstraints ret: %{public}d", ret);
    return ret;
}
} // namespace EDM
} // namespace OHOS