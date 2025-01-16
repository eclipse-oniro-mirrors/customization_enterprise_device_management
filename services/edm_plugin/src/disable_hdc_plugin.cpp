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

#include "disable_hdc_plugin.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableHdcPlugin::GetPlugin());
const std::string PERSIST_HDC_CONTROL = "persist.hdc.control";

void DisableHdcPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableHdcPlugin, bool>> ptr)
{
    EDMLOGI("DisableHdcPlugin InitPlugin...");
    std::map<std::string, std::map<IPlugin::PermissionType, std::string>> tagPermissions;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag11;
    std::map<IPlugin::PermissionType, std::string> typePermissionsForTag12;
    typePermissionsForTag11.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        "ohos.permission.ENTERPRISE_RESTRICT_POLICY");
    typePermissionsForTag11.emplace(IPlugin::PermissionType::BYOD_DEVICE_ADMIN,
        "ohos.permission.PERSONAL_MANAGE_RESTRICTIONS");
    typePermissionsForTag12.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        "ohos.permission.ENTERPRISE_MANAGE_RESTRICTIONS");
    typePermissionsForTag12.emplace(IPlugin::PermissionType::BYOD_DEVICE_ADMIN,
        "ohos.permission.PERSONAL_MANAGE_RESTRICTIONS");
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_11, typePermissionsForTag11);
    tagPermissions.emplace(EdmConstants::PERMISSION_TAG_VERSION_12, typePermissionsForTag12);

    IPlugin::PolicyPermissionConfig config = IPlugin::PolicyPermissionConfig(tagPermissions, IPlugin::ApiType::PUBLIC);
    ptr->InitAttribute(EdmInterfaceCode::DISABLED_HDC, "disabled_hdc", config, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableHdcPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableHdcPlugin::OnAdminRemove);
}

ErrCode DisableHdcPlugin::SetOtherModulePolicy(bool data)
{
    std::string newPara = data ? "false" : "true";
    if (!system::SetParameter(PERSIST_HDC_CONTROL, newPara)) {
        EDMLOGE("DisableHdcPlugin set param failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}

ErrCode DisableHdcPlugin::RemoveOtherModulePolicy()
{
    if (!system::SetParameter(PERSIST_HDC_CONTROL, "true")) {
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
