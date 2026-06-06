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

#include "disallowed_device_sudo_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisallowedDeviceSudoPlugin>());

DisallowedDeviceSudoPlugin::DisallowedDeviceSudoPlugin()
{
    EDMLOGI("DisallowedDeviceSudoPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOWED_DEVICE_SUDO;
    policyName_ = PolicyName::POLICY_DISALLOWED_DEVICE_SUDO;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
    persistParam_ = "persist.edm.sudo_disable";
}

ErrCode DisallowedDeviceSudoPlugin::CheckConflictPolicy(int32_t userId)
{
    std::string policyData;
    IPolicyManager::GetInstance()->GetPolicy("", PolicyName::POLICY_DISABLED_SUDO, policyData, userId);
    return policyData == EdmConstants::CONST_TRUE ? EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED : ERR_OK;
}
} // namespace EDM
} // namespace OHOS
