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

#include "disable_activation_lock_plugin.h"

#include "bool_serializer.h"
#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisabledActivationLockPlugin::GetPlugin());

void DisabledActivationLockPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisabledActivationLockPlugin, bool>>> ptr)
{
    EDMLOGI("DisabledActivationLockPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DIDABLED_ACTIVATION_LOCK, PolicyName::POLICY_DISABLED_ACTIVATION_LOCK,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisabledActivationLockPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisabledActivationLockPlugin::OnAdminRemove);
}

ErrCode DisabledActivationLockPlugin::SetOtherModulePolicy(bool data, int32_t userId)
{
    EDMLOGI("DisabledActivationLockPlugin OnSetPolicy...isDisallow = %{public}d", data);
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

ErrCode DisabledActivationLockPlugin::RemoveOtherModulePolicy(int32_t userId)
{
    return EdmReturnErrCode::SYSTEM_ABNORMALLY;
}

} // namespace EDM
} // namespace OHOS
