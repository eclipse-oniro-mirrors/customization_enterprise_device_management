/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "set_update_policy_plugin.h"

#include "edm_ipc_interface_code.h"
#include "iplugin_manager.h"
#include "update_policy_serializer.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(SetUpdatePolicyPlugin::GetPlugin());

void SetUpdatePolicyPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<SetUpdatePolicyPlugin, UpdatePolicy>> ptr)
{
    EDMLOGI("SetUpdatePolicyPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::SET_OTA_UPDATE_POLICY, PolicyName::POLICY_SET_UPDATE_POLICY,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_SYSTEM, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, false);
    ptr->SetSerializer(UpdatePolicySerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&SetUpdatePolicyPlugin::OnSetPolicy, FuncOperateType::SET);
}

ErrCode SetUpdatePolicyPlugin::OnSetPolicy(UpdatePolicy &policy)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}

ErrCode SetUpdatePolicyPlugin::OnGetPolicy(std::string &policyData, MessageParcel &data, MessageParcel &reply,
    int32_t userId)
{
    return EdmReturnErrCode::INTERFACE_UNSUPPORTED;
}
} // namespace EDM
} // namespace OHOS
