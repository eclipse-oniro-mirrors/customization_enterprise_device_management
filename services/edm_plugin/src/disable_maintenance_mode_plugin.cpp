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

#include "disable_maintenance_mode_plugin.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableMaintenanceModePlugin::GetPlugin());

void DisableMaintenanceModePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableMaintenanceModePlugin, bool>> ptr)
{
    EDMLOGI("DisableMaintenanceModePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_MAINTENANCE_MODE, "disabled_maintenance_mode",
        "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS", IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableMaintenanceModePlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableMaintenanceModePlugin::OnAdminRemove);
    persistParam_ = "persist.edm.maintenance_mode";
}
} // namespace EDM
} // namespace OHOS
