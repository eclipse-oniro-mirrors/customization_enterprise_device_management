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

#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowCoreDumpPlugin::GetPlugin());

void DisallowCoreDumpPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisallowCoreDumpPlugin, bool>>
    ptr)
{
    EDMLOGI("DisallowCoreDumpPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOW_CORE_DUMP, PolicyName::POLICY_DISALLOW_CORE_DUMP,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowCoreDumpPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowCoreDumpPlugin::OnAdminRemove);
    persistParam_ = "persist.edm.coredump_disable";
}
} // namespace EDM
} // namespace OHOS
