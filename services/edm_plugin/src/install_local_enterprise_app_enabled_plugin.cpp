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
 
#include "install_local_enterprise_app_enabled_plugin.h"
 
#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "edm_constants.h"
#include "iplugin_manager.h"
 
namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(InstallLocalEnterpriseAppEnabledPlugin::GetPlugin());
 
void InstallLocalEnterpriseAppEnabledPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<InstallLocalEnterpriseAppEnabledPlugin, bool>> ptr)
{
    EDMLOGI("InstallLocalEnterpriseAppEnabledPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED,
        PolicyName::POLICY_SET_INSTALL_LOCAL_ENTERPRISE_APP_ENABLED,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM, IPlugin::PermissionType::SUPER_DEVICE_ADMIN);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&InstallLocalEnterpriseAppEnabledPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&InstallLocalEnterpriseAppEnabledPlugin::OnAdminRemove);
    persistParam_ = "persist.edm.is_local_install_enable";
}
} // namespace EDM
} // namespace OHOS