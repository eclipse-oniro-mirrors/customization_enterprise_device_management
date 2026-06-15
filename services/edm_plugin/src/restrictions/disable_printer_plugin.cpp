/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "disable_printer_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisablePrinterPlugin>());

DisablePrinterPlugin::DisablePrinterPlugin()
{
    EDMLOGI("DisablePrinterPlugin InitPlugin...");
    std::map<std::string, std::map<IPlugin::PermissionType, std::string>> tagPermissions;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag11;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag12;
    typePermissionsForTag11.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_RESTRICT_POLICY);
    typePermissionsForTag12.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_11, typePermissionsForTag11);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_12, typePermissionsForTag12);
    permissionConfig_ = IPlugin::PolicyPermissionConfig(tagPermissions, IPlugin::ApiType::PUBLIC);
    policyCode_ = EdmInterfaceCode::DISABLED_PRINTER;
    policyName_ = PolicyName::POLICY_DISABLED_PRINTER;
}
} // namespace EDM
} // namespace OHOS
