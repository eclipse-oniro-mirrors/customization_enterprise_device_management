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

#include "disable_mtp_server_plugin.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableMtpServerPlugin::GetPlugin());

void DisableMtpServerPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableMtpServerPlugin, bool>> ptr)
{
    EDMLOGI("DisableMtpServerPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_MTP_SERVER, PolicyName::POLICY_DISABLED_MTP_SERVER,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableMtpServerPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableMtpServerPlugin::OnAdminRemove);
    persistParam_ = "persist.edm.mtp_server_disable";
}
} // namespace EDM
} // namespace OHOS
