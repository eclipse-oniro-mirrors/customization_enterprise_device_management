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
#include "disallow_uinput_plugin.h"

#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "input_manager.h"
 
namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowUInputPlugin::GetPlugin());
 
void DisallowUInputPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisallowUInputPlugin, bool>> ptr)
{
    EDMLOGI("DisallowUInputPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOWED_UINPUT, PolicyName::POLICY_DISALLOW_UINPUT,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowUInputPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowUInputPlugin::OnAdminRemove);
}
 
ErrCode DisallowUInputPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisallowUInputPlugin SetOtherModulePolicy: %{public}d.", data);
    return SetUInputDeviceEnabled(data);
}

ErrCode DisallowUInputPlugin::RemoveOtherModulePolicy(int32_t userId)
{
    return SetUInputDeviceEnabled(false);
}

ErrCode DisallowUInputPlugin::SetUInputDeviceEnabled(bool isDisAllow)
{
    auto inputManager = OHOS::MMI::InputManager::GetInstance();
    if (inputManager == nullptr) {
        EDMLOGI("DisallowUInputPlugin: inputManager is nullptr");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    int32_t ret = inputManager->SetEduInputDeviceEnabled(!isDisAllow);
    if (ret != ERR_OK) {
        EDMLOGI("DisallowUInputPlugin: SetEduInputDeviceEnabled failed ret: %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS