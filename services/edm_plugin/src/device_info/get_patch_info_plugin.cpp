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

#include "get_patch_info_plugin.h"

#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<GetPatchInfoPlugin>());

GetPatchInfoPlugin::GetPatchInfoPlugin()
{
    EDMLOGI("GetPatchInfoPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::GET_PATCH_INFO;
    policyName_ = PolicyName::POLICY_GET_PATCH_INFO;
    permissionConfig_ = IPlugin::PolicyPermissionConfig(EdmPermission::PERMISSION_ENTERPRISE_GET_DEVICE_INFO,
        IPlugin::PermissionType::SUPER_DEVICE_ADMIN, IPlugin::ApiType::PUBLIC);
    needSave_ = false;
}

ErrCode GetPatchInfoPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("GetPatchInfoPlugin::OnGetPolicy, open-source stub returns INTERFACE_UNSUPPORTED");
    // Open-source shell: returns 801 until an external patch-query capability is wired in.
    // Future: call the partner subsystem under FEATURE_PC_ONLY, fill vector<PatchInfo>, then
    // reply.WriteInt32(ERR_OK) + WriteUint32(size) + Marshalling each item.
    reply.WriteInt32(EdmReturnErrCode::INTERFACE_UNSUPPORTED);
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS
