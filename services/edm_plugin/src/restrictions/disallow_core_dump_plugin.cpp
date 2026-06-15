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

#include "disallow_core_dump_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisallowCoreDumpPlugin>());

DisallowCoreDumpPlugin::DisallowCoreDumpPlugin()
{
    EDMLOGI("DisallowCoreDumpPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOW_CORE_DUMP;
    policyName_ = PolicyName::POLICY_DISALLOW_CORE_DUMP;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        IPlugin::ApiType::PUBLIC);
    persistParam_ = "persist.edm.coredump_disable";
}
} // namespace EDM
} // namespace OHOS
