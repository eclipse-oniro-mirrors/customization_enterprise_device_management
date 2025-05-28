/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "disallow_add_local_account_plugin.h"

#include "edm_ipc_interface_code.h"
#include "os_account_manager.h"
#include "iplugin_manager.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisallowAddLocalAccountPlugin::GetPlugin());

const std::string ACCOUNT_CREATE_CONSTRAINT = "constraint.os.account.create";

void DisallowAddLocalAccountPlugin::InitPlugin(
    std::shared_ptr<IPluginTemplate<DisallowAddLocalAccountPlugin, bool>> ptr)
{
    EDMLOGI("DisallowAddLocalAccountPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISALLOW_ADD_LOCAL_ACCOUNT, PolicyName::POLICY_DISALLOW_ADD_LOCAL_ACCOUNT,
        EdmPermission::PERMISSION_ENTERPRISE_SET_ACCOUNT_POLICY, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisallowAddLocalAccountPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisallowAddLocalAccountPlugin::OnAdminRemove);
}

ErrCode DisallowAddLocalAccountPlugin::SetOtherModulePolicy(bool data)
{
    return SetGlobalOsAccountConstraints(data);
}

ErrCode DisallowAddLocalAccountPlugin::RemoveOtherModulePolicy()
{
    return SetGlobalOsAccountConstraints(false);
}

ErrCode DisallowAddLocalAccountPlugin::SetGlobalOsAccountConstraints(bool data)
{
    std::vector<std::string> constraints = {ACCOUNT_CREATE_CONSTRAINT};
    std::vector<int32_t> ids;
    AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (ids.empty()) {
        EDMLOGE("DisallowAddLocalAccountPlugin QueryActiveOsAccountIds failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    ErrCode ret = AccountSA::OsAccountManager::SetGlobalOsAccountConstraints(constraints, data, ids.at(0), true);
    if (FAILED(ret)) {
        EDMLOGE("DisallowAddLocalAccountPlugin SetGlobalOsAccountConstraints failed %{public}d", ret);
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
