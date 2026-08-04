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

#include "local_hota_domain_plugin.h"

#include "parameters.h"

#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(std::make_shared<LocalHotaDomainPlugin>());

LocalHotaDomainPlugin::LocalHotaDomainPlugin()
{
    EDMLOGI("LocalHotaDomainPlugin InitPlugin...");
    policyCode_ = EdmInterfaceCode::LOCAL_HOTA_DOMAIN;
    policyName_ = PolicyName::POLICY_LOCAL_HOTA_DOMAIN;
    permissionConfig_.typePermissions.emplace(IPlugin::PermissionType::SUPER_DEVICE_ADMIN,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM);
    permissionConfig_.apiType = IPlugin::ApiType::PUBLIC;
    needSave_ = false;
}

ErrCode LocalHotaDomainPlugin::OnHandlePolicy(std::uint32_t funcCode, MessageParcel &data, MessageParcel &reply,
    HandlePolicyData &policyData, int32_t userId)
{
    EDMLOGI("LocalHotaDomainPlugin OnHandlePolicy");
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode LocalHotaDomainPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    EDMLOGI("LocalHotaDomainPlugin OnGetPolicy");
    reply.WriteInt32(ERR_OK);
    std::string domain;
    reply.WriteString(domain);
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
