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

#include "disable_user_mtp_client_plugin.h"

#include <ipc_skeleton.h>
#include "bool_serializer.h"
#include "edm_constants.h"
#include "edm_errors.h"
#include "edm_ipc_interface_code.h"
#include "edm_log.h"
#include "iplugin_manager.h"
#include "os_account_manager.h"
#include "parameters.h"

namespace OHOS {
namespace EDM {
const bool REGISTER_RESULT = IPluginManager::GetInstance()->AddPlugin(DisableUserMtpClientPlugin::GetPlugin());
const std::string PERSIST_EDM_MTP_CLIENT_DISABLE = "persist.edm.mtp_client_disable";
const std::string CONSTRAINT_MTP_CLIENT_WRITE = "constraint.mtp.client.write"; // mtpClient 只读

void DisableUserMtpClientPlugin::InitPlugin(std::shared_ptr<IPluginTemplate<DisableUserMtpClientPlugin, bool>> ptr)
{
    EDMLOGI("DisableUserMtpClientPlugin InitPlugin...");
    ptr->InitAttribute(EdmInterfaceCode::DISABLE_USER_MTP_CLIENT, PolicyName::POLICY_DISABLED_USER_MTP_CLIENT,
        EdmPermission::PERMISSION_ENTERPRISE_MANAGE_RESTRICTIONS, IPlugin::PermissionType::SUPER_DEVICE_ADMIN, true);
    ptr->SetSerializer(BoolSerializer::GetInstance());
    ptr->SetOnHandlePolicyListener(&DisableUserMtpClientPlugin::OnSetPolicy, FuncOperateType::SET);
    ptr->SetOnAdminRemoveListener(&DisableUserMtpClientPlugin::OnAdminRemove);
}

ErrCode DisableUserMtpClientPlugin::OnSetPolicy(bool &data, bool &currentData, bool &mergeData,
    int32_t userId)
{
    EDMLOGI("DisableUserMtpClientPlugin::OnSetPolicy, data: %{public}d, currentData: %{public}d, "
            "mergeData: %{public}d", data, currentData, mergeData);
    std::string value = system::GetParameter(PERSIST_EDM_MTP_CLIENT_DISABLE, "false");
    if (value == "true") { // 设备级接口禁用，返回策略冲突
        return EdmReturnErrCode::CONFIGURATION_CONFLICT_FAILED;
    }

    if (mergeData) {
        currentData = data;
        return ERR_OK;
    }
    ErrCode ret = SetMtpClientPolicy(data, userId);
    EDMLOGI("DisableUserMtpClientPlugin::OnSetPolicy, SetMtpClientPolicy ret: %{public}d", ret);
    if (FAILED(ret)) {
        EDMLOGE("DisableUserMtpClientPlugin::OnSetPolicy, SetMtpClientPolicy failed");
        return EdmReturnErrCode::SYSTEM_ABNORMALLY;
    }
    currentData = data;
    mergeData = data;
    return ERR_OK;
}

ErrCode DisableUserMtpClientPlugin::OnAdminRemove(const std::string &adminName, bool &data, bool &mergeData,
    int32_t userId)
{
    EDMLOGI("DisableUserMtpClientPlugin::OnAdminRemove, adminName: %{public}s, data: %{public}d, "
            "mergeData: %{public}d", adminName.c_str(), data, mergeData);
    // admin 移除时，综合策略为只读，则最终策略不变，仍未只读
    if (mergeData) {
        return ERR_OK;
    }
    // admin 移除时，综合策略为读写，且移除的策略为只读，则更新策略为读写
    if (!mergeData && data) {
        ErrCode ret = SetMtpClientPolicy(false, userId);
        EDMLOGI("DisableUserMtpClientPlugin::OnAdminRemove, SetMtpClientPolicy ret: %{public}d", ret);
        if (FAILED(ret)) {
            EDMLOGE("DisableUserMtpClientPlugin::OnAdminRemove, SetMtpClientPolicy failed");
            return EdmReturnErrCode::SYSTEM_ABNORMALLY;
        }
    }
    return ERR_OK;
}

ErrCode DisableUserMtpClientPlugin::SetMtpClientPolicy(bool policy, int32_t userId)
{
    EDMLOGI("DisableUserMtpClientPlugin::SetMtpClientPolicy, policy: %{public}d", policy);
    std::vector<std::string> constraints;
    constraints.emplace_back(CONSTRAINT_MTP_CLIENT_WRITE);
    ErrCode ret = AccountSA::OsAccountManager::SetSpecificOsAccountConstraints(constraints, policy, userId,
        EdmConstants::DEFAULT_USER_ID, true);
    EDMLOGI("DisableUserMtpClientPlugin::SetMtpClientPolicy, SetSpecificOsAccountConstraints ret: %{public}d", ret);
    return ret;
}
} // namespace EDM
} // namespace OHOS
