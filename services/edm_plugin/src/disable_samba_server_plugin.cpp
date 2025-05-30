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

#include "disable_samba_server_plugin.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableSambaServerPlugin::GetPlugin());

void DisableSambaServerPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableSambaServerPlugin, bool>> ptr)
{
    EDMLOGI("DisableSambaServerPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_SAMBA_SERVER, PolicyName::POLICY_DISABLED_SAMBA_SERVER,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableSambaServerPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableSambaServerPlugin::OnAdminRemove);
    persistParam_ = "persist.edm.samba_server_disable";
}
} // namespace EDM
} // namespace OHOS
