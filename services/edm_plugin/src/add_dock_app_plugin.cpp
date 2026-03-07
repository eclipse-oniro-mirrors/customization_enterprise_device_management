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

#include "add_dock_app_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {

const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<AddDockAppPlugin>());

AddDockAppPlugin::AddDockAppPlugin()
{
    policyCode_ = EdmInterfaceCode::ADD_DOCK_APP;
    policyName_ = PolicyName::POLICY_ADD_DOCK_APP;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_APPLICATION);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

ErrCode AddDockAppPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data,
    MessageParcel &reply, HandlePolicyData &policyData, int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode AddDockAppPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data,
    MessageParcel &reply, int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS