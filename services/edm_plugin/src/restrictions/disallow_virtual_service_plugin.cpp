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

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"
 
namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisallowVirtualServicePlugin>());
 
DisallowVirtualServicePlugin::DisallowVirtualServicePlugin()
{
    EDMLOGI("DisallowVirtualServicePlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOW_VIRTUAL_SERVICE;
    policyName_ = PolicyName::POLICY_DISALLOW_VIRTUAL_SERVICE;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
}
 
ErrCode DisallowVirtualServicePlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    if (data) {
        if (!system::SetParameter("persist.edm.disallow_virtual_service", "anco|linux|win")) {
            EDMLOGE("set disallow virtual service true failed.");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    } else {
        if (!system::SetParameter("persist.edm.disallow_virtual_service", "")) {
            EDMLOGE("set disallow virtual service false failed.");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS