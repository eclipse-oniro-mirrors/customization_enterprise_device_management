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

#include "disallow_rs232_plugin.h"

#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowRs232Plugin::GetPlugin());

void DisallowRs232Plugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisallowRs232Plugin, bool>>
    ptr)
{
    EDMLOGI("DisallowRs232Plugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOW_RS232, PolicyName::POLICY_DISALLOW_RS232,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowRs232Plugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowRs232Plugin::OnAdminRemove);
    persistParam_ = "persist.edm.rs232_serial_disable";
}
} // namespace EDM
} // namespace OHOS
