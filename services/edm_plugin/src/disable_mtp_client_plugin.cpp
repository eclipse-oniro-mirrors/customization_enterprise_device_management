/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
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

#include "disable_mtp_client_plugin.h"

#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "os_account_manager.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableMtpClientPlugin::GetPlugin());

void DisableMtpClientPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableMtpClientPlugin, bool>> ptr)
{
    EDMLOGI("DisableMtpClientPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_MTP_CLIENT, PolicyName::POLICY_DISABLED_MTP_CLIENT,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableMtpClientPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableMtpClientPlugin::OnAdminRemove);
    persistParam_ = "persist.edm.mtp_client_disable";
}

ErrCode DisableMtpClientPlugin::OnSetPolicy(bool &data, bool &currentData, bool &mergeData, int32_t userId)
{
    EDMLOGI("DisableMtpClientPlugin::OnSetPolicy, data: %{public}d, currentData: %{public}d, mergeData: %{public}d",
            data, currentData, mergeData);
    std::vector<AccountSA::OsAccountInfo> accounts;
    ErrCode ret = OHOS::AccountSA::OsAccountManager::QueryAllCreatedOsAccounts(accounts);
    EDMLOGI("DisableMtpClientPlugin::OnSetPolicy, QueryAllCreatedOsAccounts ret: %{public}d", ret);
    if (FAILED(ret) || accounts.empty()) {
        EDMLOGE("DisableMtpClientPlugin::OnSetPolicy, QueryAllCreatedOsAccounts failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    for (size_t i = 0; i < accounts.size(); i++) {
        auto policyManager = IPolicyManager::GetInstance();
        std::string disableUserMtpClientPolicy;
        policyManager->GetPolicy("", PolicyName::POLICY_DISABLED_USER_MTP_CLIENT, disableUserMtpClientPolicy,
            accounts[i].GetLocalId());
        if (disableUserMtpClientPolicy == "true" && data == true) { // 如果用户级存在只读策略时，设备级想设置为禁用策略，则返回策略冲突
            EDMLOGE("DisableMtpClientPlugin configuration conflict");
            return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
        }
    }

    if (mergeData) {
        currentData = data;
        return ERR_OK;
    }
    if (!persistParam_.empty() && !system::SetParameter(persistParam_, data ? "true" : "false")) {
        EDMLOGE("DisableMtpClientPlugin set param failed.");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = data;
    mergeData = data;
    return ERR_OK;
}
} // namespace EDM
} // namespace OHOS
