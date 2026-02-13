/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
#include "get_ext_info_plugin.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "ext_info_type.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<GetExtInfoPlugin>());

const char* const BUNDLE_NAME = "com.ohos.adminprovisioning";

GetExtInfoPlugin::GetExtInfoPlugin()
{
    policyCode_ = EdmInterfaceCode::GET_EXT_INFO;
    policyName_ = PolicyName::POLICY_GET_EXT_INFO;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_MANAGE_EDM_POLICY);
    permissionConfig_.apiType = IPlugin::ApiType::SYSTEM;
    needSave_ = false;
}

ErrCode GetExtInfoPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    int32_t type = data.ReadInt32();
    EDMLOGI("GetExtInfoPlugin::OnGetPolicy, type = %{public}d", type);
    if (type == static_cast<int32_t>(ExtInfoType::ADMIN_PROVISIONING_INFO)) {
        reply.WriteInt32(ERR_OK);
        reply.WriteString(BUNDLE_NAME);
        return ERR_OK;
    }
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS