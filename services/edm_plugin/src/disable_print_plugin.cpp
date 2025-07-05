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

#include "disable_print_plugin.h"

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
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisablePrintPlugin::GetPlugin());
const std::string CONSTRAINT_PRINT = "constraint.print";

void DisablePrintPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisablePrintPlugin, bool>> ptr)
{
    EDMLOGI("DisablePrintPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISABLED_PRINT, PolicyName::POLICY_DISABLED_PRINT,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisablePrintPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisablePrintPlugin::OnAdminRemove);
}


ErrCode DisablePrintPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisablePrintPlugin::SetPrintPolicy, userId: %{public}d, policy: %{public}d", userId, policy);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_PRINT);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(constraints, policy, userId,
        EdmConstants::DEFAULT_USER_ID, true);
    EDMLOGI("DisablePrintPlugin::SetPrintPolicy, SetSpecificOsAccountConstraints ret: %{public}d", ret);
    return ret;
}

ErrCode DisablePrintPlugin::RemoveOtherModulePolicy(int32_t userId)
{
    EDMLOGI("DisablePrintPlugin::RemoveOtherModulePolicy, userId: %{public}d", userId);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_PRINT);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(constraints, false, userId,
        EdmConstants::DEFAULT_USER_ID, true);
    EDMLOGI("DisablePrintPlugin::SetPrintPolicy, SetSpecificOsAccountConstraints ret: %{public}d", ret);
    return ret;
}
} // namespace EDM
} // namespace OHOS