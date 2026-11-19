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

#include "disallow_system_sharing_panel_plugin.h"

#include <ipc_skeleton.h>
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "os_account_manager.h"


namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<DisallowSystemSharingPanelPlugin>());
const std::string CONSTRAINT_COLLABORATION_SYSTEM_SHARE = "constraint.collaboration.systemShare";

DisallowSystemSharingPanelPlugin::DisallowSystemSharingPanelPlugin()
{
    EDMLOGI("DisallowSystemSharingPanelPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOW_SYSTEM_SHARING_PANEL;
    policyName_ = PolicyName::POLICY_DISALLOW_SYSTEM_SHARING_PANEL;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = true;
}

ErrCode DisallowSystemSharingPanelPlugin::SetOtherModulePolicy(bool policy, int32_t userId)
{
    EDMLOGI("DisallowSystemSharingPanelPlugin::SetOtherModulePolicy, policy: %{public}d", policy);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_COLLABORATION_SYSTEM_SHARE);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(
        constraints, policy, userId, EdmConstants::DEFAULT_USER_ID, true);
    if (FAILED(ret)) {
        EDMLOGE("DisallowSystemSharingPanelPlugin::OnSetPolicy Failed, ret: %{public}d", ret);
        return EdmReturnErrCode::EXECUTE_TIME_OUT;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
