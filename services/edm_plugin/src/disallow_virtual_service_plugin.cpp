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
#include "disallow_virtual_service_plugin.h"

#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"
 
namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowVirtualServicePlugin::GetPlugin());
 
void DisallowVirtualServicePlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisallowVirtualServicePlugin, bool>>
    ptr)
{
    EDMLOGI("DisallowVirtualServicePlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOW_VIRTUAL_SERVICE, PolicyName::POLICY_DISALLOW_VIRTUAL_SERVICE,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowVirtualServicePlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowVirtualServicePlugin::OnAdminRemove);
}
 
ErrCode DisallowVirtualServicePlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    if (data) {
        if (!system::SetParameter("persist.edm.disallow_virtual_service", "anco|linux|win")) {
            EDMLOGE("disallow_virtual_service anco|linux|win failed.");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    } else {
        if (!system::SetParameter("persist.edm.disallow_virtual_service", "")) {
            EDMLOGE("allow_virtual_service.anco|linux|win failed.");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS