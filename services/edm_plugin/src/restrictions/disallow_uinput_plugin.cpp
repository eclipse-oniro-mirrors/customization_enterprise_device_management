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
#include "disallow_uinput_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "input_manager.h"
 
namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisallowUInputPlugin>());
 
DisallowUInputPlugin::DisallowUInputPlugin()
{
    EDMLOGI("DisallowUInputPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::DISALLOWED_UINPUT;
    policyName_ = PolicyName::POLICY_DISALLOW_UINPUT;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
}
 
ErrCode DisallowUInputPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisallowUInputPlugin SetOtherModulePolicy: %{public}d.", data);
    auto inputManager = OHOS::MMI::InputManager::GetInstance();
    if (inputManager == nullptr) { //LCOV_EXCL_BR_LINE
        EDMLOGE("DisallowUInputPlugin: inputManager is nullptr");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = inputManager->DisableInputEventDispatch(data);
    if (ret != ERR_OK) { //LCOV_EXCL_BR_LINE
        EDMLOGE("DisallowUInputPlugin: DisableInputEventDispatch failed ret: %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS