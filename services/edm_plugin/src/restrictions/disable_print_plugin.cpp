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
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "os_account_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisablePrintPlugin>());
const std::string CONSTRAINT_PRINT = "constraint.print";

DisablePrintPlugin::DisablePrintPlugin()
{
    EDMLOGI("DisablePrintPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISABLED_PRINT;
    policyName_ = PolicyName::POLICY_DISABLED_PRINT;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
}


ErrCode DisablePrintPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisablePrintPlugin::SetPrintPolicy, policy: %{public}d", data);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_PRINT);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(constraints, data, userId,
        EdmConstants::DEFAULT_USER_ID, true);
    EDMLOGI("DisablePrintPlugin::SetPrintPolicy, SetSpecificOsAccountConstraints ret: %{public}d", ret);
    return ret;
}
} // namespace EDM
} // namespace OHOS