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
#include "disable_set_biometrics_and_screenLock_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisableSetBiometricsAndScreenLockPlugin>());

DisableSetBiometricsAndScreenLockPlugin::DisableSetBiometricsAndScreenLockPlugin()
{
    EDMLOGI("DisableSetBiometricsAndScreenLockPlugin InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, EdmPermission::PERMISSION_ENTERPRISE_SET_USER_RESTRICTION);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    policyCode_ = EdmInterfaceCode::DISABLE_SET_BIOMETRICS_AND_SCREENLOCK;
    policyName_ = PolicyName::POLICY_SET_BIOMETRICS_AND_SCREENLOCK;
    persistParam_ = "persist.edm.set_biometrics_and_screenLock_disable";
}
} // namespace EDM
} // namespace OHOS
