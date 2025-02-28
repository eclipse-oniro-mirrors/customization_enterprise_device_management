/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "inactive_user_freeze_plugin.h"

#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(InactiveUserFreezePlugin::GetPlugin());

void InactiveUserFreezePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<InactiveUserFreezePlugin, bool>> ptr)
{
    EDMLOGI("InactiveUserFreezePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::INACTIVE_USER_FREEZE, "inactive_user_freeze",
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&InactiveUserFreezePlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&InactiveUserFreezePlugin::OnAdminRemove);
    persistParam_ = "persist.edm.inactive_user_freeze";
}
} // namespace EDM
} // namespace OHOS
