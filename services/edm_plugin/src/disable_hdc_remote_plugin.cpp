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
 
#include "disable_hdc_remote_plugin.h"
 
#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"
 
namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableHdcRemotePlugin::GetPlugin());
 
void DisableHdcRemotePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableHdcRemotePlugin, bool>> ptr)
{
    EDMLOGI("DisableHdcRemotePlugin InitPlugin...");
    std::map<IPlugin::PermissionType, std::string> typePermissions;
    typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS);
    typePermissions.emplace(IPlugin::PermissionType::BYOD_DEVICE_ADMIN,
        EdmPermission::PERMISSION_PERSONAL_MANAGE_RESTRICTIONS);
    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(typePermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::DISABLED_HDC_REMOTE, PolicyName::POLICY_DISABLED_HDC_REMOTE, config, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableHdcRemotePlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableHdcRemotePlugin::OnAdminRemove);
    persistParam_ = "persist.edm.hdc_remote_disable";
}
 
ErrCode DisableHdcRemotePlugin::RemoveOtherModulePolicy(int32_t userId)
{
    if (!system::SetParameter("persist.edm.hdc_remote_disable", "false")) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS