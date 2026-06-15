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

#include "disallowed_telephony_call_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(
    std::make_shared<DisallowedTelephonyCallPlugin>());

DisallowedTelephonyCallPlugin::DisallowedTelephonyCallPlugin()
{
    EDMLOGI("DisallowedTelephonyCallPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOWED_TELEPHONY_CALL;
    policyName_ = PolicyName::POLICY_DISALLOWED_TELEPHONY_CALL;
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    persistParam_ = "persist.edm.telephony_call_disable";
}
} // namespace EDM
} // namespace OHOS
