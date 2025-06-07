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

#include "disallowed_nfc_plugin.h"

#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowedNFCPlugin::GetPlugin());

void DisallowedNFCPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisallowedNFCPlugin, bool>> ptr)
{
    EDMLOGI("DisallowedNFCPlugin InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_NFC, PolicyName::POLICY_DISALLOWED_NFC, config, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowedNFCPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowedNFCPlugin::OnAdminRemove);
    persistParam_ = "persist.edm.nfc_disable";
}
} // namespace EDM
} // namespace OHOS