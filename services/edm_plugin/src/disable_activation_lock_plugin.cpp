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

#include "edm_ipc_interface_code.h"
#include "parameters.h"
#include "iplugin_manager.h"
#include "edm_constants.h"
#include "ipolicy_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT =
    IPluginManager::GetInstance()->AddPlugin(std::make_shared<DisableActivationLockPlugin>());

DisableActivationLockPlugin::DisableActivationLockPlugin()
{
    policyCode_ = EdmInterfaceCode::DISABLED_ACTIVATION_LOCK;
    policyName_ = PolicyName::POLICY_DISABLED_ACTIVATION_LOCK;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

ErrCode DisableActivationLockPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode DisableActivationLockPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode DisableActivationLockPlugin::OnAdminRemove(const std::string &adminName, const std::string &currentJsonData,
    const std::string &mergeJsonData, int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS
