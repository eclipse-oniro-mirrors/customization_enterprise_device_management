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

#include "disallow_open_file_boost_plugin.h"

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
    DisallowOpenFileBoostPlugin::GetPlugin());
const std::string CONSTRAINT_OPENFILEBOOST = "constraint.preview.openFileBoost";

void DisallowOpenFileBoostPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowOpenFileBoostPlugin, bool>> ptr)
{
    EDMLOGI("DisallowOpenFileBoostPlugin InitPlugin...");
    ptr->InitAttribute(
        EdmInterfaceCode::DISALLOWED_FILEBOOST_OPEN,
        PolicyName::POLICY_DISALLOWED_OPEN_FILE_BOOST,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowOpenFileBoostPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowOpenFileBoostPlugin::OnAdminRemove);
}

ErrCode DisallowOpenFileBoostPlugin::OnSetPolicy(
    bool &data, bool &currentData, bool &mergeData, int32_t userId)
{
    EDMLOGI("DisallowOpenFileBoostPlugin::OnSetPolicy, data: %{public}d, currentData: %{public}d, "
            "mergeData: %{public}d", data, currentData, mergeData);
    if (mergeData) {
        currentData = data;
        return ERR_OK;
    }
    ErrCode ret = SetOpenFileBoostPolicy(data, userId);
    if (FAILED(ret)) {
        EDMLOGE("DisallowOpenFileBoostPlugin::OnSetPolicy Failed, ret: %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = data;
    mergeData = data;
    return ERR_OK;
}

ErrCode DisallowOpenFileBoostPlugin::OnAdminRemove(
    const std::string &adminName, bool &data, bool &mergeData, int32_t userId)
{
    EDMLOGI("DisallowOpenFileBoostPlugin::OnAdminRemove, adminName: %{public}s, data: %{public}d, "
            "mergeData: %{public}d", adminName.c_str(), data, mergeData);
    if (mergeData) {
        return ERR_OK;
    }
    if (data) {
        ErrCode ret = SetOpenFileBoostPolicy(false, userId);
        if (FAILED(ret)) {
            EDMLOGE("DisallowOpenFileBoostPlugin::OnAdminRemove Failed, ret: %{public}d", ret);
        }
    }
    return ERR_OK;
}

ErrCode DisallowOpenFileBoostPlugin::SetOpenFileBoostPolicy(bool policy, int32_t userId)
{
    EDMLOGI("DisallowOpenFileBoostPlugin::SetOpenFileBoostPolicy, policy: %{public}d", policy);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_OPENFILEBOOST);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(
        constraints, policy, userId, EdmConstants::DEFAULT_USER_ID, true);
    EDMLOGI("DisallowOpenFileBoostPlugin SetSpecificOsAccountConstraints ret: %{public}d", ret);
    return ret;
}
} // namespace EDM
} // namespace OHOS
